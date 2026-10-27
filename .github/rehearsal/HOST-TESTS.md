# Updater test brief: upgrade a running install from `master` to the release candidate, with real Docker

You are testing, on a real Docker host, whether an installed cvENGINE (the version on `master`, v1.2.1) upgrades cleanly to the next
release (`develop`). GitHub's CI already runs the happy path; what it cannot do is what a real server does: cron's bare environment, an update
that is interrupted part-way, a small-memory host, and a second update. Those are your tests. Do NOT make code changes or open PRs; report.

## Safety rules (read first)
- Work only in a scratch directory. Never touch an existing cvENGINE install, its containers, volumes or `.env`. Before starting run
  `docker ps -a` and `docker volume ls`: if anything is named `cvengine*`, stop and use `COMPOSE_PROJECT_NAME=cvrehearsal` for everything below and
  skip the overlay mode (it hard-codes the project name `cvengine`). Make sure ports 443, 8082 and 8000 are free (plain mode publishes them), else use overlay mode.
- Do not print `.env`, tokens or passwords in your report. Remove everything you created at the end (`docker compose down -v`, scratch dir).
- This is a throwaway install with throwaway data. Real customer data must not be on this host.

## Setup (the rehearsal scripts are the same ones CI runs; they take `$HOME` as the install root and `$GITHUB_WORKSPACE` as the repo)
```
export HOME=/srv/cv-rehearsal; mkdir -p $HOME; cd $HOME
git clone https://github.com/hevnsnt/CVEngine.git ws && export GITHUB_WORKSPACE=$HOME/ws
cd ws && git fetch origin --tags
export BASE_REF=master CANDIDATE_REF=origin/develop     # record `git rev-parse origin/develop` in your report
.github/rehearsal/prepare.sh                            # builds $HOME/origin.git (master) and $HOME/cvengine, writes $HOME/candidate.sha
.github/rehearsal/install-base.sh plain                 # installs MASTER, waits for site and workers (10-20 min first time)
.github/rehearsal/seed.sh                               # small seed
cd $HOME/cvengine && dc() { docker compose "$@"; }; dc exec -T web python3 manage.py shell < $GITHUB_WORKSPACE/.github/rehearsal/seed-rich.py   # 5000 CVE matches, 2500 with the old wording
```
Snapshot the schema now: `dc exec -T db psql -U $POSTGRES_USER -d $POSTGRES_DB -Atc "select table_name||'.'||column_name||'|'||is_nullable||'|'||coalesce(column_default,'NONE') from information_schema.columns where table_schema='public' order by 1" > $HOME/schema-before.txt`
Each scenario below starts from a FRESH master install (down -v, re-run install-base.sh + seeds) unless it says otherwise. Between scenarios
`git --git-dir=$HOME/origin.git update-ref refs/heads/master $(cat $HOME/base.sha)` to put the origin back.

To "approve" an update exactly as the web container does:
```
git --git-dir=$HOME/origin.git update-ref refs/heads/master "$(cat $HOME/candidate.sha)"
cd $HOME/cvengine && cp $HOME/candidate.sha web/.update-approved && printf 'master\n' > web/.update-branch
```
The installed (master) `scripts/apply-update.sh` performs the upgrade; the update log is `$(python3 scripts/update-state.py directory)/update.log`.

## Scenarios
**S1. Through the cron watcher with cron's environment.** Approve, then run the watcher as cron would, not from your shell:
`env -i PATH=/usr/bin:/bin HOME=/root scripts/update-watch.sh 3000 >/dev/null 2>&1 &` (adjust HOME to the real user). Wait for `web/.update-approved` to disappear.
Then run `.github/rehearsal/verify.sh plain` and the extra checks below. Record the total time and `docker compose ps`.

**S2. Interrupted update: kill the updater at each stage, then let it retry.** Master's updater is the one that runs, so this shows what a real host does.
Start `setsid scripts/apply-update.sh & PG=$!`; when the trigger below appears in `ps`, run `kill -KILL -- -$PG`. Then restore normal conditions
(re-run `env -i ... scripts/update-watch.sh 3000` / `scripts/apply-update.sh`, with the approval file still present or re-created) and see whether the install ends
healthy. Triggers: (a) `pgrep -f 'compose.* build'` (during the build); (b) `pgrep -f 'manage.py migrate'` (during migrate); (c) `pgrep -f collectstatic`
(after migrate, before the containers are recreated); (d) `pgrep -f 'force-recreate'` (while recreating).
For each: after the retry, does `git rev-parse HEAD` equal the candidate, are there pending migrations (`dc exec -T web python3 manage.py showmigrations --plan | grep -c '^\[ \]'`),
is the running web container on the new code (`dc exec -T web python3 -c "import agentapi"`, and `curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/mcp/` must be 401 or 200, never 500),
what does the update log say, and does Settings > Updates / `web/.update-phase` say "done" while it is NOT healthy? A "done" on an unhealthy install is the bug we are hunting.
Also record whether scanning is left paused afterwards (`dc exec -T web python3 manage.py shell -c "from cveFeed.models import ScanControl; print(list(ScanControl.objects.values())[:3])"`).

**S3. Small host.** Our production host has 4.6 GB RAM and 2 CPUs. Sample `free -m` and `docker stats --no-stream` every 3 s during S1's build and update; report the peak used
memory, the peak of the build, whether anything was OOM-killed (`dmesg | grep -i 'killed process'`, `docker ps -a --filter status=exited`), and the build time. If the host is
much larger, say so; do not pretend it is representative.

**S4. Old containers on the new schema (the window between migrate and recreate).** Do S2(c) (kill after migrate, before recreate) and, WITHOUT restarting, from the old
celery container run a feed-style insert and read the logs for `IntegrityError` / `null value in column`:
`dc exec -T celery python3 manage.py shell -c "from cveFeed.models import CVEEntry; from django.utils import timezone as t; n=t.now(); CVEEntry.objects.create(cve_id='CVE-2099-1',title='t',affected=[],published_at=n,created_at=n,synced_at=n)"`
(Expect it to FAIL on develop as of 2f98c6f for column `local_only`; a later commit adds database defaults. Re-run on the newer candidate and report if it passes.)

**S5. A second update with the new scripts.** After S1 succeeded, add an empty-effect commit to the origin master (e.g. a one-line change to `docs/UPDATES.md`), approve it,
and apply it. The now-installed (new) `scripts/apply-update.sh` runs. Check the update log says what it did, `web/.commit` is the new commit, and the install is healthy.
Then approve the same commit again: the log must say "already at" and nothing may be rebuilt (`grep -c ' build ' calls`/log).

**S6. Data and features after the upgrade (S1 install).**
- `showmigrations --plan | grep -c '^\[ \]'` is 0; `dc exec -T db psql ... ` schema now vs `$HOME/schema-before.txt`: list new columns on tables that existed before that are NOT NULL with default `NONE`.
- No CVE match or triage row still says `invalid product correlation` (they must read `different product`): `... CVEMatch.objects.filter(ai_reason__contains='invalid product').count()`.
- MCP: create a token (`dc exec -T web python3 manage.py shell`, see `agentapi.auth.create_token`), POST JSON-RPC `initialize` then `tools/list` to `/mcp/`: 200 and more than 20 tools.
- Log in as the admin and open: /, /cve/, /cve/graph/, /cve/_all/keys/, Settings and its Updates/Tailscale/runZero tabs, a host page, a finding page. Report any status >= 500 and any traceback in `dc logs web`.
- `dc exec -T celery celery -A reNgine.tasks inspect active_queues` includes `wpscan_queue`. `dc exec -T web nmap --script-help ssl-cert | head -1` works (amd64 uses the RPM binary; say the CPU architecture).
- Restart the whole stack (`dc down; dc up -d`, no `-v`): everything comes back healthy with the data intact.

## Report back (one block, no secrets)
Host: CPU arch, cores, RAM, Docker version, OS. Refs: master SHA, candidate SHA. A table: scenario / PASS | FAIL | PARTIAL / one-line finding. For every FAIL or PARTIAL:
the exact commands, the relevant 20-40 lines of the update log and `dc logs`, and what the install looked like afterwards. Say plainly which results are from MASTER's
updater (the one real hosts run for this upgrade) and which from the candidate's. If you could not run something, say so; do not infer.
