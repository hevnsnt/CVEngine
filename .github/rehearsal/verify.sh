#!/usr/bin/env bash
# The updated install: every service running, the site answering on its own port, no unapplied migration, the update recorded, the workers
# answering, the data still there (and the duplicate addresses merged), and for the overlay install the proxy still off port 443.
set -euo pipefail
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
cd "$HOME/cvengine"
fail=0
bad() { echo "::error::$*"; fail=1; }

running=$(dc ps --status running --services)
for service in db redis web celery celery-beat proxy; do
  grep -qx "$service" <<<"$running" || bad "$service is not running"
done
wait_for_site 300 || fail=1

if [ "$(head -n1 web/.commit 2>/dev/null)" != "$(cat "$HOME/candidate.sha")" ]; then
  bad "web/.commit is '$(head -n1 web/.commit 2>/dev/null)', not the candidate $(cat "$HOME/candidate.sha")"
fi
if [ "$(git rev-parse HEAD)" != "$(cat "$HOME/candidate.sha")" ]; then bad "the checkout is at $(git rev-parse --short HEAD), not the candidate"; fi

pending=$(dc exec -T web python3 manage.py showmigrations --plan | grep -c '^\[ \]' || true)
[ "$pending" = 0 ] || bad "$pending migrations are not applied"
dc exec -T web python3 manage.py check || bad "manage.py check failed"
# The workers were restarted by the update and take as long to come up as after any restart.
wait_for_workers 600 || bad "the Celery workers do not answer after the update"

dc exec -T web python3 manage.py shell <<'PY' || bad "the data check failed"
from django.db.models import Count
from startScan.models import Subdomain, IpAddress
from targetApp.models import Domain
assert Domain.objects.filter(name='rehearsal.example').exists(), 'the target is gone'
# discovery and host pipelines run in the background of an updated install and add rows of their own: the domain itself, and scan-owned copies of
# the seeded names (rehearsal.example does not resolve, so a copy holds no address). The update has to keep what the seed made: the four hosts
# that no scan owns, each still linked to the address it was given.
wanted = {'h0.rehearsal.example': '203.0.113.10', 'h1.rehearsal.example': '203.0.113.10', 'h2.rehearsal.example': '203.0.113.10',
          'www.rehearsal.example': '203.0.113.11'}
hosts = Subdomain.objects.filter(target_domain__name='rehearsal.example', name__in=wanted, scan_history__isnull=True)
assert {h.name for h in hosts} == set(wanted), f'seeded hosts missing: {sorted(set(wanted) - {h.name for h in hosts})}'
for h in hosts:
    got = sorted(h.ip_addresses.values_list('address', flat=True))
    assert got == [wanted[h.name]], f'{h.name} has {got}, not its seeded address {wanted[h.name]}'
dups = IpAddress.objects.values('address').annotate(c=Count('id')).filter(c__gt=1).count()
assert dups == 0, f'{dups} addresses are still stored more than once'
print('DATA OK')
PY

# The old containers ran on the new schema for a while: nothing the update added may make the old code's inserts fail
if [ -f "$HOME/schema-before.txt" ]; then
  "$GITHUB_WORKSPACE/.github/rehearsal/schema.sh" check "$HOME/schema-before.txt" || bad "the update added a column the old code cannot insert around"
fi
# The application works on the new schema: the MCP endpoint and its token lookup, tools that read the changed tables, the main pages
dc exec -T web python3 manage.py shell < "$GITHUB_WORKSPACE/.github/rehearsal/smoke.py" || bad "the functional smoke test failed (see the lines above)"
# The rewrite is a data migration (0092): it only reaches rows that existed when the update ran, so it can be checked only when the installed
# (base) version does not have it yet. A base that already ran it leaves the old wording the seed adds afterwards as it is.
base_has_rewrite() { git -C "$GITHUB_WORKSPACE" cat-file -e "$(cat "$HOME/base.sha"):web/cveFeed/migrations/0092_reword_different_product_closures.py" 2>/dev/null; }
if [ "$(cat "$HOME/base.sha")" != "$(cat "$HOME/candidate.sha")" ] && ! base_has_rewrite; then
  dc exec -T web python3 manage.py shell <<'PY' || bad "the stored closure wording was not rewritten"
from cveFeed.models import CVEMatch, TriageVerdict
old = CVEMatch.objects.filter(ai_reason__contains='invalid product correlation').count() + TriageVerdict.objects.filter(reason__contains='invalid product correlation').count()
new = CVEMatch.objects.filter(ai_reason__contains='different product').count()
assert old == 0, f'{old} rows still carry the first wording'
if CVEMatch.objects.exists():
    assert new > 0 or CVEMatch.objects.filter(ai_reason__contains='Closed automatically').count() == 0, 'no row carries the reworded closure'
print('WORDING OK', new)
PY
fi
# captured first: `inspect | grep -q` fails under pipefail when grep exits early and the producer gets SIGPIPE, even though it matched
queues=$(dc exec -T celery celery -A reNgine.tasks inspect active_queues -t 20 2>/dev/null || true)
grep -q wpscan_queue <<<"$queues" || { bad "no worker consumes wpscan_queue"; grep -oE "'name': '[a-z_]+'" <<<"$queues" | sort -u | head -20; }

if [ "$(mode)" = overlay ]; then
  ports=$(docker ps --filter "label=com.docker.compose.service=proxy" --format '{{.Ports}}')
  echo "proxy ports: $ports"
  grep -q '127.0.0.1:18443->443' <<<"$ports" || bad "the proxy is not on 127.0.0.1:18443 any more"
  ! grep -q '0.0.0.0:443' <<<"$ports" || bad "the proxy took port 443"
fi

# The base was installed without a broker password (install-base.sh): the update must have generated one and recreated Redis with it
if grep -qE '^REDIS_PASSWORD=.+' .env; then
  password=$(grep -E '^REDIS_PASSWORD=' .env | tail -n1 | cut -d= -f2-)
  dc exec -T redis redis-cli ping 2>&1 | grep -q NOAUTH || bad "Redis answers without the password"
  dc exec -T redis redis-cli -a "$password" --no-auth-warning ping | grep -q PONG || bad "Redis does not answer with the password"
  if [ "$(mode)" = overlay ]; then
    grep -qxF "REDIS_PASSWORD=$password" .env.vps || bad "the overlay's env file (.env.vps) does not carry the broker password"
  fi
else
  bad "the update left the Redis broker without a password"
fi

# The built-in scanner (docs/BUILTIN-SCANNER.md), on by default from 1.4: where the candidate's compose file has it, the update must have started it
# with no one running anything, it must have enrolled itself and be heard from, and its heartbeats must reach the server. A first enrollment can
# take a few minutes after the update (the server writes it when celery starts), so this waits up to ten.
if dc config --services 2>/dev/null | grep -qx scanner; then
  grep -qx scanner <<<"$(dc ps --status running --services)" || bad "the built-in scanner is not running after the update"
  scanner_ok=0
  for _ in $(seq 1 60); do
    if dc exec -T scanner python3 -m client.control heartbeat >/dev/null 2>&1 \
        && dc exec -T web python3 manage.py shell -c "from agentapi import builtin_scanner as b; s = b.status(); raise SystemExit(0 if s.get('enrolled') and s.get('live') else 1)" >/dev/null 2>&1; then
      scanner_ok=1; break
    fi
    sleep 10
  done
  if [ "$scanner_ok" = 1 ]; then
    echo "The built-in scanner enrolled itself and checks in:"
    dc exec -T web python3 manage.py shell -c "from agentapi import builtin_scanner as b; print(b.status())" || true
  else
    bad "the built-in scanner did not enrol and check in within ten minutes of the update"
    dc exec -T web python3 manage.py shell -c "from agentapi import builtin_scanner as b; print(b.status())" || true
    dc logs --tail 80 scanner || true
  fi

  # SN-8: the scanner runs with every capability dropped but NET_RAW and SYS_CHROOT, and still does what the raw-socket tools do. NET_ADMIN is allowed only
  # when the image running is one from before the reduction (nmap and naabu with cap_net_admin as a file capability, which cannot start without it:
  # scripts/scanner.sh adds it for such an image alone), so a scanner that keeps it for a current image fails here.
  cid=$(dc ps -q scanner | head -n 1)
  caps=$(docker inspect -f '{{json .HostConfig.CapDrop}} {{json .HostConfig.CapAdd}}' "$cid")
  echo "scanner capabilities (drop, add): $caps"
  grep -q '"ALL"' <<<"${caps%% *}" || bad "the built-in scanner does not drop every capability"
  for cap in NET_RAW SYS_CHROOT; do grep -q "\"$cap\"" <<<"${caps#* }" || bad "the built-in scanner lacks $cap"; done
  if grep -q '"NET_ADMIN"' <<<"${caps#* }"; then
    dc exec -T scanner getcap /usr/local/bin/nmap | grep -q cap_net_admin || bad "the built-in scanner keeps NET_ADMIN although its image no longer needs it"
    echo "(this scanner image is from before the reduction, so it keeps NET_ADMIN)"
  fi
  # a SYN scan, OS detection, a UDP probe and naabu's SYN scan through the service itself, at its own loopback only (never another host)
  dc exec -T scanner nmap -sS -Pn -n -p 1 --reason 127.0.0.1 | tee "$HOME/scanner-syn.txt"
  grep -q '1/tcp *closed' "$HOME/scanner-syn.txt" || bad "nmap -sS through the built-in scanner did not run"
  dc exec -T scanner nmap -sS -O -Pn -n -p 1,22 127.0.0.1 > "$HOME/scanner-os.txt" 2>&1 || bad "nmap -O through the built-in scanner failed"
  grep -qi 'requires root privileges' "$HOME/scanner-os.txt" && bad "nmap -O wanted root privileges in the built-in scanner"
  dc exec -T scanner nmap -sU -Pn -n -p 53 --max-retries 1 127.0.0.1 > "$HOME/scanner-udp.txt" 2>&1 || bad "nmap -sU through the built-in scanner failed"
  grep -qi 'requires root privileges' "$HOME/scanner-udp.txt" && bad "nmap -sU wanted root privileges in the built-in scanner"
  dc exec -T scanner naabu -host 127.0.0.1 -p 8000,5432,6379 -scan-type s -silent -nc -warm-up-time 1 || bad "naabu's SYN scan through the built-in scanner failed"
fi

[ "$fail" = 0 ] && echo "The updated install is healthy." || exit 1
