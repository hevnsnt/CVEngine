"""Update check against the project's GitHub repository, with an administrator in the loop.

A beat task (``check_for_updates``, twice a day) asks GitHub for the head of the configured branch and compares it
with the installed commit. When there is something newer, superusers see a banner and a Settings > Updates page
where they approve or dismiss it. The web container never updates itself and has no Docker or git access: approving
only writes the approved commit to ``.update-approved`` in the application directory (the host's ``web/``), and
``scripts/apply-update.sh`` on the host (cron or systemd timer, see scripts/install-updater.sh) fast-forwards the
checkout to exactly that commit and rebuilds. The installed commit is the first line of ``.commit``, written by
``make up`` / ``make build`` and by the updater script.

Pure helpers take their HTTP function as a parameter so they are testable without a network.
"""
import json
import logging
import math
import os
import re
import time
from datetime import datetime, timezone as dt_timezone

import requests
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

API = 'https://api.github.com'
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')
BRANCH_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$')
SHA_RE = re.compile(r'^[0-9a-f]{40}$')
MAX_COMMITS = 20
PHASE_VALUES = ('idle', 'draining', 'applying', 'done', 'failed')
HEARTBEAT_ALIVE_SECONDS = 180  # scripts/update-watch.sh reports every 15 seconds; this is a few missed minutes


class UpdateError(Exception):
    pass


def valid_repo(repo):
    return bool(REPO_RE.match(repo or '')) and '..' not in repo


def valid_branch(branch):
    return bool(BRANCH_RE.match(branch or '')) and '..' not in branch and not branch.endswith(('/', '.lock'))


def _file(name):
    return os.path.join(settings.BASE_DIR, name)


def installed_sha():
    """The commit this installation was built from ('' when unknown)."""
    try:
        with open(_file('.commit')) as f:
            first = f.readline().strip().lower()
    except OSError:
        first = ''
    if SHA_RE.match(first):
        return first
    env = os.environ.get('CVENGINE_COMMIT', '').strip().lower()
    return env if SHA_RE.match(env) else ''


def host_updater():
    """Whether the host-side watcher (scripts/update-watch.sh) is listening: it writes ``.updater-heartbeat`` every 15 seconds. The web
    container cannot act on an approval itself, so an admin needs to know when nothing on the host will. ``seen`` is False when the
    file has never been written (not installed, or an older updater that does not report)."""
    try:
        with open(_file('.updater-heartbeat')) as f:
            at = float(json.load(f)['at'])
    except (OSError, ValueError, KeyError, TypeError):
        return {'seen': False, 'alive': False, 'age_seconds': None}
    age = time.time() - at
    if not math.isfinite(age) or age < -60:
        return {'seen': False, 'alive': False, 'age_seconds': None}
    age = int(max(0, age))
    return {'seen': True, 'alive': age <= HEARTBEAT_ALIVE_SECONDS, 'age_seconds': age}


MODES = ('manual', 'auto')


def read_mode():
    """How updates are installed: ``manual`` (the default: nothing is installed until an administrator approves it) or ``auto`` (a new
    version found by the check is approved for them). Kept in ``.update-mode`` beside the approval so the host scripts read the same
    answer; a missing, unreadable or unexpected file is manual. Nothing changes the code of an install unless this says ``auto``."""
    try:
        with open(_file('.update-mode')) as f:
            return 'auto' if f.read(16).strip() == 'auto' else 'manual'
    except OSError:
        return 'manual'


def set_mode(mode):
    if mode not in MODES:
        raise UpdateError('the update mode must be manual or auto')
    tmp = _file('.update-mode.tmp')
    with open(tmp, 'w') as f:
        f.write(mode + '\n')
    os.replace(tmp, _file('.update-mode'))


def auto_approve(row):
    """In automatic mode, approve the version the check just found, as the administrator would have. Returns whether it did."""
    if read_mode() != 'auto' or state(row)['status'] != 'available':
        return False
    approve(row, 'automatic')
    return True


def read_phase():
    """scripts/apply-update.sh's current progress ({phase, detail, scans_running, changed_at}), 'idle' when there is
    no phase file (no update has ever run, or the previous one's result was already superseded) or it cannot be
    read as the shape the script writes."""
    try:
        with open(_file('.update-phase.json')) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {'phase': 'idle', 'detail': '', 'scans_running': None, 'changed_at': None}
    phase = data.get('phase')
    if phase not in PHASE_VALUES:
        return {'phase': 'idle', 'detail': '', 'scans_running': None, 'changed_at': None}
    scans_running = data.get('scans_running')
    changed_at = data.get('changed_at')
    return {
        'phase': phase,
        'detail': str(data.get('detail') or '')[:200],
        'scans_running': scans_running if isinstance(scans_running, int) and scans_running >= 0 else None,
        'changed_at': datetime.fromtimestamp(changed_at, tz=dt_timezone.utc).isoformat()
                      if isinstance(changed_at, (int, float)) else None,
    }


def _headers(token):
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'CVEngine-updater'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return headers


def _first_line(text):
    return (text or '').strip().splitlines()[0][:300] if (text or '').strip() else ''


def fetch_latest(repo, branch, token='', installed='', get=requests.get):
    """Ask GitHub for the branch head and how far ahead of ``installed`` it is.
    Returns {sha, message, url, date, behind_by (None if unknown), commits}. Raises UpdateError with a readable reason."""
    if not valid_repo(repo) or not valid_branch(branch):
        raise UpdateError('the repository or branch name is not valid')
    try:
        resp = get(f'{API}/repos/{repo}/commits/{branch}', headers=_headers(token), timeout=20)
    except requests.RequestException as exc:
        raise UpdateError(f'could not reach GitHub: {exc}')
    if resp.status_code == 404:
        raise UpdateError('repository or branch not found (a private repository needs a token)')
    if resp.status_code in (401, 403):
        raise UpdateError('GitHub refused the request (check the token, or the rate limit was hit)')
    if resp.status_code != 200:
        raise UpdateError(f'GitHub answered {resp.status_code}')
    data = resp.json()
    sha = str(data.get('sha', '')).lower()
    if not SHA_RE.match(sha):
        raise UpdateError('unexpected answer from GitHub')
    commit = data.get('commit') or {}
    date = ((commit.get('committer') or {}).get('date')) or ''
    out = {'sha': sha, 'message': _first_line(commit.get('message')), 'url': str(data.get('html_url', ''))[:300],
           'date': date, 'behind_by': None, 'commits': []}
    if not installed:
        return out
    if installed == sha:
        out['behind_by'] = 0
        return out
    try:
        cmp = get(f'{API}/repos/{repo}/compare/{installed}...{sha}', headers=_headers(token), timeout=20)
    except requests.RequestException:
        return out
    if cmp.status_code == 200:
        body = cmp.json()
        if body.get('status') in ('behind', 'identical'):
            out['behind_by'] = 0  # the installation is already at or past the remote head
        else:
            out['behind_by'] = int(body.get('ahead_by') or 0)
            out['commits'] = [{'sha': str(c.get('sha', ''))[:7], 'message': _first_line((c.get('commit') or {}).get('message'))}
                              for c in reversed(body.get('commits') or [])][:MAX_COMMITS]
    return out


def update_available(row, installed):
    return bool(row.latest_sha and row.latest_sha != installed and row.behind_by != 0)


def check(row=None, get=requests.get):
    """Run one check and store the result on the settings row."""
    from cveFeed.models import UpdateSettings
    row = row or UpdateSettings.current()
    row.last_checked_at = timezone.now()
    try:
        found = fetch_latest(row.repo, row.branch, row.token, installed_sha(), get=get)
    except UpdateError as exc:
        row.last_error = str(exc)[:300]
        row.save(update_fields=['last_checked_at', 'last_error'])
        return row
    row.last_error = ''
    row.latest_sha, row.latest_message, row.latest_url = found['sha'], found['message'], found['url']
    try:
        row.latest_date = datetime.fromisoformat(found['date'].replace('Z', '+00:00')) if found['date'] else None
    except ValueError:
        row.latest_date = None
    row.behind_by, row.commits = found['behind_by'], found['commits']
    row.save()
    sync_applied(row)
    return row


def sync_applied(row):
    """Forget an approval once the installed commit has caught up with it."""
    if row.approved_sha and installed_sha() == row.approved_sha:
        row.approved_sha, row.approved_by, row.approved_at = '', '', None
        row.save(update_fields=['approved_sha', 'approved_by', 'approved_at'])
        _remove_flag()


def _remove_flag():
    for name in ('.update-approved', '.update-branch'):
        try:
            os.remove(_file(name))
        except OSError:
            pass


def approve(row, user):
    """Record the administrator's approval of the commit currently shown, and hand it to the host updater."""
    if not SHA_RE.match(row.latest_sha or ''):
        raise UpdateError('there is no update to approve; run a check first')
    if not update_available(row, installed_sha()):
        raise UpdateError('this installation is already up to date')
    tmp = _file('.update-approved.tmp')
    with open(tmp, 'w') as f:
        f.write(row.latest_sha + '\n')
    # the branch is written first: the host reads it when it sees the approval, and moves its checkout there when it differs
    branch_tmp = _file('.update-branch.tmp')
    with open(branch_tmp, 'w') as f:
        f.write(row.branch + '\n')
    os.replace(branch_tmp, _file('.update-branch'))
    os.replace(tmp, _file('.update-approved'))
    row.approved_sha, row.approved_by, row.approved_at = row.latest_sha, getattr(user, 'username', user), timezone.now()
    row.save(update_fields=['approved_sha', 'approved_by', 'approved_at'])
    return row


def cancel_approval(row):
    _remove_flag()
    row.approved_sha, row.approved_by, row.approved_at = '', '', None
    row.save(update_fields=['approved_sha', 'approved_by', 'approved_at'])


def dismiss(row):
    """Hide the banner for this commit; a newer one asks again."""
    row.dismissed_sha = row.latest_sha
    row.save(update_fields=['dismissed_sha'])


def state(row):
    """What the API and the banner show. ``status``: disabled | error | up_to_date | available | approved | dismissed."""
    from cveFeed.models import ScanControl

    installed = installed_sha()
    available = update_available(row, installed)
    if not row.enabled:
        status = 'disabled'
    elif row.approved_sha and row.approved_sha == row.latest_sha and available:
        status = 'approved'
    elif available and row.dismissed_sha == row.latest_sha:
        status = 'dismissed'
    elif available:
        status = 'available'
    elif row.last_error and not row.latest_sha:
        status = 'error'
    else:
        status = 'up_to_date'
    phase = read_phase()
    # A phase older than the approval is the result of an earlier update (a failure from last time), not of this one.
    if row.approved_at and phase['changed_at'] and datetime.fromisoformat(phase['changed_at']) < row.approved_at:
        phase = {'phase': 'idle', 'detail': '', 'scans_running': None, 'changed_at': None}
    # Read live, not from the phase file: apply-update.sh's own pause/release calls can fail independently of the
    # phase it last wrote, and an admin's manual resume can clear it between runs without rewriting the phase file.
    control = ScanControl.current()
    return {
        'status': status, 'enabled': row.enabled, 'repo': row.repo, 'branch': row.branch, 'has_token': bool(row.token),
        'installed': installed[:7], 'installed_known': bool(installed),
        'latest': row.latest_sha[:7], 'latest_message': row.latest_message, 'latest_url': row.latest_url,
        'latest_date': row.latest_date.isoformat() if row.latest_date else None, 'behind_by': row.behind_by,
        'commits': row.commits, 'last_checked_at': row.last_checked_at.isoformat() if row.last_checked_at else None,
        'last_error': row.last_error, 'approved_by': row.approved_by,
        'approved_at': row.approved_at.isoformat() if row.approved_at else None,
        'phase': phase['phase'], 'phase_detail': phase['detail'], 'phase_scans_running': phase['scans_running'],
        'phase_changed_at': phase['changed_at'],
        'scans_paused_by_update': bool(control.paused and control.paused_by_update),
        'host_updater': host_updater(),
        'mode': read_mode(),
    }
