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
hosts = Subdomain.objects.filter(target_domain__name='rehearsal.example')
assert hosts.count() == 4, f'{hosts.count()} hosts, expected 4'
assert all(h.ip_addresses.exists() for h in hosts), 'a host lost its address'
dups = IpAddress.objects.values('address').annotate(c=Count('id')).filter(c__gt=1).count()
assert dups == 0, f'{dups} addresses are still stored more than once'
print('DATA OK')
PY

if [ "$(mode)" = overlay ]; then
  ports=$(docker ps --filter "label=com.docker.compose.service=proxy" --format '{{.Ports}}')
  echo "proxy ports: $ports"
  grep -q '127.0.0.1:18443->443' <<<"$ports" || bad "the proxy is not on 127.0.0.1:18443 any more"
  ! grep -q '0.0.0.0:443' <<<"$ports" || bad "the proxy took port 443"
fi

if grep -qE '^REDIS_PASSWORD=.+' .env; then
  password=$(grep -E '^REDIS_PASSWORD=' .env | tail -n1 | cut -d= -f2-)
  dc exec -T redis redis-cli ping 2>&1 | grep -q NOAUTH || bad "Redis answers without the password"
  dc exec -T redis redis-cli -a "$password" --no-auth-warning ping | grep -q PONG || bad "Redis does not answer with the password"
fi

[ "$fail" = 0 ] && echo "The updated install is healthy." || exit 1
