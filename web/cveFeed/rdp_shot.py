"""Shodan-style RDP login-screen capture: for a server nmap already confirmed is RDP and showed will accept a connection
without Network Level Authentication (``cveFeed.service_intel.rdp_without_nla``), a Sentinel (task kind ``rdp_shot``) takes one screenshot of the
pre-authentication screen and the configured AI model reads who, if anyone, it shows signed in.

This is never attempted against a server that requires NLA: CredSSP must complete, with real credentials, before the
server sends any graphical frame, so there is nothing to capture and nothing is guessed. The Sentinel connects with the "none" auth
method, which sends no credentials at all, and the capture is discarded here unless it is a real, non-blank frame. The username the AI
reads back is not a secret; it is exactly what the screen already shows to anyone who can reach the port.

The capture runs nowhere but on a Sentinel (``sentinel_dispatch.NEVER_LOCAL``): with none able to take it the servers stay due. This module
validates what comes back (size, a real frame), stores it, one per host and port per window (the service ledger, ``CVENGINE_TTL_RDP_SHOT``),
and queues the AI reading.
"""
import io
import json
import logging
import os
import re

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SERVICE = 'rdp-shot'
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


def max_hosts():
    try:
        return max(1, int(os.environ.get('CVENGINE_RDP_SHOT_MAX_HOSTS', MAX_HOSTS_PER_SCAN)))
    except ValueError:
        return MAX_HOSTS_PER_SCAN


def enabled():
    return os.environ.get('CVENGINE_RDP_SHOT', '1').strip().lower() not in ('0', 'false', 'no', 'off')


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


def queue_reading(shot, scan, sub, address, port, png_bytes):
    """Ask the AI model what the login screen shows: one AI job (cveFeed.ai_jobs) carrying the image, answered by the AI reviewer
    container; ``job_answer`` stores the reading on ``shot`` when it lands. Returns True when queued (False with no AI configured, which
    is recorded on the shot as before)."""
    import base64
    from cveFeed import ai_jobs
    if not ai_jobs.ai_on():
        _set(shot.pk, ai_error='No AI model is configured')
        return False
    ai_jobs.enqueue('rdp_screenshot', 'rdp_screenshot', system=VISION_SYSTEM, parts=[{'text': VISION_PROMPT}],
                    image={'media_type': 'image/png', 'data': base64.b64encode(png_bytes).decode()}, project=shot.project_id,
                    context={'shot': shot.pk, 'scan': scan.pk, 'sub': sub.pk, 'address': address, 'port': port, 'image_hash': shot.image_hash},
                    dedupe=f'rdp_screenshot:{shot.pk}', priority=6)
    return True


def _set(pk, **fields):
    from cveFeed.models import RdpScreenshot
    RdpScreenshot.objects.filter(pk=pk).update(**fields)


def job_answer(job, text):
    """The model read the screen: stored on the screenshot when it is still the image that was read, and a signed-in account becomes
    the informational finding, as when the server read it itself."""
    from cveFeed.models import RdpScreenshot
    from startScan.models import ScanHistory, Subdomain
    ctx = job.context
    shot = RdpScreenshot.objects.filter(pk=ctx.get('shot'), image_hash=ctx.get('image_hash')).first()
    if shot is None:
        return None  # a newer capture replaced it: its own reading is on its way
    parsed = _parse_vision_reply(text)
    if parsed is None:
        _set(shot.pk, ai_error='the AI model did not answer in the expected format')
        return None
    _set(shot.pk, logged_in_user=parsed['logged_in_user'], ai_summary=parsed['summary'], ai_error='')
    scan = ScanHistory.objects.select_related('domain').filter(pk=ctx.get('scan')).first()
    sub = Subdomain.objects.filter(pk=ctx.get('sub')).first()
    if parsed['logged_in_user'] and scan is not None and sub is not None:
        _record_logged_in_finding(scan, sub, ctx.get('address'), ctx.get('port'), parsed)
    return None


def job_failure(job, category, detail):
    _set(job.context.get('shot'), ai_error=f'the AI model could not read it ({category})')


def _allowed(project, name, address):
    """Whether a session may be opened to ``address`` for the host ``name`` now: the organization's exclusions are read afresh (an
    unreadable list stops the stage rather than clearing everything), and an address the scanner may not reach is never connected to."""
    from cveFeed.exclusions import excluded_names, normalize
    from targetApp.target_types import is_scannable_ip
    return normalize(name) not in excluded_names(project, strict=True) and is_scannable_ip(address, project=project)


def rdp_candidates(scan):
    """``[(Subdomain, address, port number)]`` for this scan's open ports that nmap showed accept RDP without NLA, leaving out hosts the
    organization excluded and addresses the scanner may not reach."""
    from cveFeed import service_intel
    from startScan.models import Subdomain, open_ports
    from cveFeed.bounty_gate import Gate
    gate, project = Gate(blocked=()), scan.domain.project_id  # a bug bounty program's scope: a host it does not name is never connected to
    out = []
    project = scan.domain.project_id
    for sub in Subdomain.objects.filter(scan_history=scan).prefetch_related('ip_addresses__ports'):
        if gate.refusal(project, sub.name, unattended=False):
            continue
        for ip in sub.ip_addresses.all():
            if not _allowed(project, sub.name, ip.address):
                continue
            for port in open_ports(ip):
                if service_intel.is_rdp_port(port) and service_intel.rdp_without_nla(port):
                    out.append((sub, ip.address, port.number))
    return out


def run_for_scan(scan_id, reader=None, force=False):
    """Screenshot every confirmed, NLA-free RDP server this scan found through a Sentinel, store the image, and have the AI read who it
    shows signed in: the reading is queued for the AI reviewer container (``queue_reading``), or done by ``reader(png)`` when one is
    given. A capture or read failure is recorded and never raised; it leaves any previous screenshot in place. With no scanner able to take the
    work the servers stay due and nothing is recorded. Returns a summary dict (``read`` counts the readings done or queued)."""
    from cveFeed import ledger
    from cveFeed.models import RdpScreenshot
    from startScan.models import ScanHistory
    from agentapi import sentinel_dispatch
    from reNgine.resources import ScannerUnavailable
    if not enabled():
        return {'attempted': 0, 'skipped': 'disabled'}
    scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
    project = scan.domain.project_id
    candidates = rdp_candidates(scan)
    if not candidates:
        return {'attempted': 0}
    assets = [f'{addr}:{port}' for _sub, addr, port in candidates]
    covered = set() if force else ledger.fresh(SERVICE, assets, project)
    todo = [(sub, addr, port) for (sub, addr, port), asset in zip(candidates, assets) if asset not in covered][:max_hosts()]
    if not todo:
        return {'attempted': 0, 'captured': 0, 'read': 0, 'reused': len(covered)}
    try:
        sentinel_dispatch.scanner_or_local(scan.domain.project, 'rdp_shot')  # raises ScannerUnavailable when none is live: the kind has no local path
    except ScannerUnavailable as exc:  # no scanner can take it and no session may be opened from here: the servers stay due
        return {'attempted': 0, 'captured': 0, 'read': 0, 'reused': len(covered), 'skipped': f'no scanner could take this work ({exc.kind})'}
    shots, waiting = {}, None  # index -> PNG bytes (None: nothing was painted); an index not in here was not taken by a scanner
    todo = [(sub, addr, port) for sub, addr, port in todo if _allowed(project, sub.name, addr)]  # excluded since the candidates were listed
    try:
        for index, result in sentinel_dispatch.dispatch_each(scan.domain.project, 'rdp_shot', todo, lambda item: {'address': item[1], 'port': item[2]},
                                                             scan=scan, label_of=lambda item: f'{item[1]}:{item[2]}', ips_of=lambda item: [item[1]]):
            if result is not None:
                shots[index] = sentinel_dispatch.rdp_image(result)
    except ScannerUnavailable as exc:  # what the scanner captured is stored below; the rest stays due
        waiting = exc
    attempted = captured = read_ok = 0
    for index, (sub, addr, port) in enumerate(todo):
        asset = f'{addr}:{port}'
        if index not in shots:
            continue  # no scanner took it: stays due, nothing recorded
        attempted += 1
        png = shots[index]
        if not png or len(png) > MAX_IMAGE_BYTES or not is_meaningful(png):
            ledger.record(SERVICE, [asset], project, scan, 'failed')
            continue
        rel_path, image_hash = save_image(scan, addr, port, png)
        captured += 1
        ai = reader(png) if reader is not None else {}
        shot, _ = RdpScreenshot.objects.update_or_create(
            project_id=project, host=sub.name, port=port,
            defaults={'domain_id': scan.domain_id, 'address': addr, 'image_path': rel_path, 'image_hash': image_hash,
                      'logged_in_user': ai.get('logged_in_user', ''), 'ai_summary': ai.get('summary', ''),
                      'ai_error': ai.get('error', ''), 'captured_at': timezone.now()})
        if reader is None:
            read_ok += queue_reading(shot, scan, sub, addr, port, png)
        elif 'error' not in ai:
            read_ok += 1
        if ai.get('logged_in_user'):
            _record_logged_in_finding(scan, sub, addr, port, ai)
        ledger.record(SERVICE, [asset], project, scan)
    out = {'attempted': attempted, 'captured': captured, 'read': read_ok, 'reused': len(covered)}
    if waiting is not None:
        out['skipped'] = f'no scanner could take this work ({waiting.kind})'
    return out


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
