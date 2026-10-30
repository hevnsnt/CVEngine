"""Update check against the project's GitHub repository, with an administrator in the loop.

A beat task (``check_for_updates``, twice a day) asks GitHub for the head of the configured branch and compares it
with the installed commit. When there is something newer, superusers see a banner and a Settings > Updates page
where they approve or dismiss it. The web container never updates itself and has no Docker or git access: approving
only writes the approved commit to ``.update-approved`` in the application directory (the host's ``web/``), and
``scripts/apply-update.sh`` on the host (cron or systemd timer, see scripts/install-updater.sh) fast-forwards the
checkout to exactly that commit and rebuilds. The installed commit is the first line of ``.commit``, written by
``make up`` / ``make build`` and by the updater script. Only the host has git: it compares that commit with the tracked branch and
publishes the answer as ``.upstream-state.json`` (see ``upstream_state``), so a server with commits of its own is compared by the commit it
shares with the branch, GitHub being unable to say anything about commits it has never seen.

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


RELEASE_BRANCHES = ('master', 'main')  # the branches a release is cut from; any other branch is a development line


def branch_warning(branch):
    """Why an administrator should look twice before updating from ``branch``, or '' for a release branch. Any branch may be tracked
    (a fork's own, develop for a test server); nothing is refused, but the approval says plainly that it is not a release."""
    if (branch or '') in RELEASE_BRANCHES:
        return ''
    return (f'This server tracks the branch "{branch}", not a release branch ({" or ".join(RELEASE_BRANCHES)}). '
            'It gets work in progress that has not been released or fully tested.')


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


UPSTREAM_STALE_SECONDS = 3 * 86400  # the host refreshes it every half hour while its updater runs; this is days of silence


def write_source(row):
    """Tell the host which repository and branch to compare the build with (``.update-source``: ``owner/name branch``)."""
    tmp = _file('.update-source.tmp')
    try:
        with open(tmp, 'w') as f:
            f.write(f'{row.repo} {row.branch}\n')
        os.replace(tmp, _file('.update-source'))
    except OSError:
        pass  # a read-only mount: the host then compares nothing, and the banner works from what GitHub says


def upstream_state(row):
    """What the host found when it compared the running build with the tracked branch (scripts/update-state.py ``upstream``), as
    ``(state, note)``. ``state`` is ``{base, upstream, ahead, behind}``: ``base`` the newest commit the build shares with the branch,
    ``ahead`` the commits of this server's own, ``behind`` the branch's commits it lacks; None when there is nothing usable. ``note`` says
    why not when an administrator should know (the host could not fetch the branch, or its answer is for another source or an older build)."""
    try:
        with open(_file('.upstream-state.json')) as f:
            data = json.loads(f.read(4096))
        at = float(data['at'])
    except (OSError, ValueError, KeyError, TypeError):
        return None, ''
    if not isinstance(data, dict) or not math.isfinite(at):
        return None, ''
    if str(data.get('repo', '')).lower() != row.repo.lower() or data.get('branch') != row.branch:
        return None, ''  # about a source that is no longer the one tracked; the next host run replaces it
    installed = installed_sha()
    if installed and data.get('installed') != installed:
        return None, ''  # about the build before this one
    if time.time() - at > UPSTREAM_STALE_SECONDS:
        return None, 'The host has not compared this server with the update source for days (is the host updater running?).'
    if data.get('error'):
        return None, f'The host could not compare this server with {row.repo} {row.branch}: {str(data["error"])[:160]}'
    base, tip = str(data.get('base', '')), str(data.get('upstream', ''))
    ahead, behind = data.get('ahead'), data.get('behind')
    if not (SHA_RE.match(base) and SHA_RE.match(tip) and isinstance(ahead, int) and isinstance(behind, int) and ahead >= 0 and behind >= 0):
        return None, ''
    return {'base': base, 'upstream': tip, 'ahead': ahead, 'behind': behind}, ''


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


CERT_WARN_DAYS = 30  # the host renews the web interface certificate with this many days left (scripts/renew-certs.sh); a warning at that point means it did not
CERT_STALE_SECONDS = 3 * 86400  # the host checks twice a day; this is days of silence


def certificate(now=None):
    """The web interface certificate as scripts/renew-certs.sh last reported it (``.cert-status.json``, written on the host): when it ends,
    how many days remain now, when it was last checked and renewed, and a ``problem`` sentence when an admin should act (a failed renewal,
    fewer than 30 days left, expired, or no check for days). ``known`` is False when nothing was ever reported (not an installation with the
    bundled certificate authority, or an older updater): then nothing is claimed and nothing warns."""
    unknown = {'known': False, 'not_after': None, 'days_left': None, 'state': 'unknown', 'last_checked_at': None, 'last_renewed_at': None,
               'last_result': None, 'error': None, 'problem': None}
    try:
        with open(_file('.cert-status.json')) as f:
            data = json.load(f)
        checked, ends = float(data['checked_at']), data.get('not_after')
        ends = float(ends) if ends is not None else None
    except (OSError, ValueError, KeyError, TypeError):
        return unknown
    if not math.isfinite(checked) or (ends is not None and not math.isfinite(ends)):
        return unknown
    now = now if now is not None else time.time()
    renewed = data.get('renewed_at')

    def iso(seconds):
        return datetime.fromtimestamp(seconds, tz=dt_timezone.utc).isoformat()
    out = dict(unknown, known=True, last_checked_at=iso(checked), last_result=data.get('result') if data.get('result') in ('kept', 'issued', 'external', 'failed') else None,
               last_renewed_at=iso(float(renewed)) if isinstance(renewed, (int, float)) and math.isfinite(renewed) else None,
               error=str(data.get('error') or '')[:200] or None)
    problems = []
    if ends is not None:
        out['not_after'] = iso(ends)
        out['days_left'] = math.floor((ends - now) / 86400)
        out['state'] = 'expired' if ends <= now else 'expiring' if out['days_left'] < CERT_WARN_DAYS else 'ok'
        if out['state'] == 'expired':
            problems.append('The web interface certificate has expired, so browsers warn on every visit.')
        elif out['state'] == 'expiring' and out['last_result'] == 'external':
            problems.append(f"The web interface certificate expires in {out['days_left']} days. It was not issued by this server's own authority, so it is not "
                            f"renewed automatically: renew it as its issuer describes (docs/HOSTING-ONLINE.md).")
        elif out['state'] == 'expiring':
            problems.append(f"The web interface certificate expires in {out['days_left']} days; it should have been renewed automatically by now.")
    else:
        out['state'] = 'ok' if out['last_result'] != 'failed' else 'unknown'
    if out['last_result'] == 'failed':
        problems.append(f"Renewing the web interface certificate failed: {out['error'] or 'no reason was given'}.")
    if now - checked > CERT_STALE_SECONDS:
        problems.append(f"The certificate renewal check has not run for {int((now - checked) // 86400)} days (is the host updater or cron running?).")
    if problems and out['last_result'] != 'external':
        problems.append('On the server, run scripts/renew-certs.sh; its log is cert.log in .git/cvengine-update.')
    out['problem'] = ' '.join(problems) or None
    return out


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


def update_in_progress(max_age_seconds=2 * 3600):
    """True while the host script reports it is draining or applying an update. A phase not refreshed for ``max_age_seconds`` is a
    script that died, not an update in progress, so it never blocks an operator for good."""
    phase = read_phase()
    if phase['phase'] not in ('draining', 'applying'):
        return False
    changed = phase['changed_at']
    if not changed:
        return True
    return (datetime.now(dt_timezone.utc) - datetime.fromisoformat(changed)).total_seconds() <= max_age_seconds


def _headers(token):
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'CVEngine-updater'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    return headers


def _first_line(text):
    return (text or '').strip().splitlines()[0][:300] if (text or '').strip() else ''


def fetch_latest(repo, branch, token='', installed='', get=None):
    """Ask GitHub for the branch head and how far ahead of ``installed`` it is.
    Returns {sha, message, url, date, behind_by (None if unknown), commits, reference_known}: ``reference_known`` is False when GitHub answered "not
    found" for ``installed`` (it has never seen that commit: a fork's own, or a server's unpushed one), which is not the same as not being able to
    ask. Raises UpdateError with a readable reason."""
    if not valid_repo(repo) or not valid_branch(branch):
        raise UpdateError('the repository or branch name is not valid')
    get = get or requests.get  # looked up now, so a test that replaces requests.get is heard
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
           'date': date, 'behind_by': None, 'commits': [], 'reference_known': True}
    if not installed:
        return out
    if installed == sha:
        out['behind_by'] = 0
        return out
    try:
        cmp = get(f'{API}/repos/{repo}/compare/{installed}...{sha}', headers=_headers(token), timeout=20)
    except requests.RequestException:
        return out
    if cmp.status_code == 404:
        out['reference_known'] = False
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
    """Whether the branch has commits the build lacks. Not known when GitHub has never seen the build's commit and the host has not said which
    commit the build shares with the branch: then nothing is claimed either way (``state`` reports it as ``unknown``)."""
    return bool(row.latest_sha and row.latest_sha != installed and row.behind_by != 0 and not row.reference_unknown)


def check(row=None, get=None):
    """Run one check and store the result on the settings row."""
    from cveFeed.models import UpdateSettings
    row = row or UpdateSettings.current()
    row.last_checked_at = timezone.now()
    write_source(row)
    shared = (upstream_state(row)[0] or {}).get('base')  # what GitHub knows of a build with commits of its own
    try:
        found = fetch_latest(row.repo, row.branch, row.token, shared or installed_sha(), get=get)
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
    row.behind_by, row.commits, row.reference_unknown = found['behind_by'], found['commits'], not found['reference_known']
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


def local_commits(row):
    """How many commits of its own the build has on top of the tracked branch (0 when none or not known)."""
    host, _ = upstream_state(row)
    return host['ahead'] if host else 0


def approve(row, user):
    """Record the administrator's approval of the commit currently shown, and hand it to the host updater."""
    if not SHA_RE.match(row.latest_sha or ''):
        raise UpdateError('there is no update to approve; run a check first')
    if not update_available(row, installed_sha()):
        raise UpdateError('this installation is already up to date, or cannot tell whether it is (see its status)')
    own = local_commits(row)
    if own:
        raise UpdateError(f'this server has {own} commit{"s" if own != 1 else ""} of its own, so the update cannot be applied for you (it moves the checkout '
                          f'forward, never merges): merge {row.branch} into it by hand, then deploy')
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
    """What the API and the banner show. ``status``: disabled | error | up_to_date | available | approved | dismissed | diverged (the branch has new
    commits and this server has commits of its own, so nothing can fast-forward it) | unknown (GitHub has never seen the build's commit and
    the host has not said which commit it shares with the branch)."""
    from cveFeed.models import ScanControl

    installed = installed_sha()
    available = update_available(row, installed)
    own = local_commits(row)
    host, note = upstream_state(row)
    if not row.enabled:
        status = 'disabled'
    elif row.approved_sha and row.approved_sha == row.latest_sha and available and not own:
        status = 'approved'
    elif available and row.dismissed_sha == row.latest_sha:
        status = 'dismissed'
    elif available and own:
        status = 'diverged'  # the branch moved and so did this server: nothing can fast-forward it
    elif available:
        status = 'available'
    elif row.reference_unknown and row.latest_sha and row.latest_sha != installed:
        status = 'unknown'
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
        'status': status, 'enabled': row.enabled, 'repo': row.repo, 'branch': row.branch, 'branch_warning': branch_warning(row.branch),
        'has_token': bool(row.token),
        'installed': installed[:7], 'installed_known': bool(installed),
        'local_commits': host['ahead'] if host else None, 'common': host['base'][:7] if host else '', 'host_comparison': note,
        'latest': row.latest_sha[:7], 'latest_message': row.latest_message, 'latest_url': row.latest_url,
        'latest_date': row.latest_date.isoformat() if row.latest_date else None, 'behind_by': row.behind_by,
        'commits': row.commits, 'last_checked_at': row.last_checked_at.isoformat() if row.last_checked_at else None,
        'last_error': row.last_error, 'approved_by': row.approved_by,
        'approved_at': row.approved_at.isoformat() if row.approved_at else None,
        'phase': phase['phase'], 'phase_detail': phase['detail'], 'phase_scans_running': phase['scans_running'],
        'phase_changed_at': phase['changed_at'],
        'scans_paused_by_update': bool(control.paused and control.paused_by_update),
        'host_updater': host_updater(),
        'certificate': certificate(),
        'mode': read_mode(),
    }
