#!/usr/bin/env bash
# Puts data in the installed version, including what a newer version has to clean up: the same IP address stored three times. An installed
# version that already refuses duplicate addresses (v1.2.0 and later) keeps one row, and the rest of the data is seeded as before.
set -euo pipefail
. "$GITHUB_WORKSPACE/.github/rehearsal/lib.sh"
dc exec -T web python3 manage.py shell <<'PY'
from django.db import IntegrityError, transaction
from django.utils import timezone
from dashboard.models import Project
from targetApp.models import Domain
from startScan.models import Subdomain, IpAddress
now = timezone.now()
project = Project.objects.filter(slug='rehearsal').first() or Project.objects.create(name='Rehearsal', slug='rehearsal', insert_date=now)
domain = Domain.objects.create(name='rehearsal.example', project=project, insert_date=now)
same = []
for _ in range(3):
    try:
        with transaction.atomic():
            same.append(IpAddress.objects.create(address='203.0.113.10'))
    except IntegrityError:
        same.append(IpAddress.objects.filter(address='203.0.113.10').order_by('id').first())  # the installed version refuses a second row
other = IpAddress.objects.create(address='203.0.113.11')
for index, ip in enumerate(same):
    Subdomain.objects.create(target_domain=domain, name=f'h{index}.rehearsal.example').ip_addresses.add(ip)
Subdomain.objects.create(target_domain=domain, name='www.rehearsal.example').ip_addresses.add(other)
print('SEEDED', Subdomain.objects.filter(target_domain=domain).count(), 'hosts', IpAddress.objects.count(), 'addresses')
PY
# DEBUG (throwaway): log every statement that deletes an address link, an address or a host
dc exec -T web python3 manage.py shell <<'PY'
from django.db import connection
with connection.cursor() as c:
    c.execute("""CREATE OR REPLACE FUNCTION dbg_iplink() RETURNS trigger AS $$ BEGIN
      RAISE WARNING 'IPLINK-DEL table=% old=% query=%', TG_TABLE_NAME, to_jsonb(OLD), left(current_query(), 400); RETURN OLD; END; $$ LANGUAGE plpgsql""")
    for t in ('"startScan_subdomain_ip_addresses"', '"startScan_ipaddress"', '"startScan_subdomain"'):
        c.execute('DROP TRIGGER IF EXISTS dbg_iplink_trg ON ' + t)
        c.execute('CREATE TRIGGER dbg_iplink_trg AFTER DELETE ON ' + t + ' FOR EACH ROW EXECUTE FUNCTION dbg_iplink()')
print('DEBUG TRIGGERS SET')
PY
# more data (5000 CVE matches, half of them with the wording a newer version rewrites) and the schema the update starts from
dc exec -T web python3 manage.py shell < "$GITHUB_WORKSPACE/.github/rehearsal/seed-rich.py"
"$GITHUB_WORKSPACE/.github/rehearsal/schema.sh" snapshot "$HOME/schema-before.txt"
