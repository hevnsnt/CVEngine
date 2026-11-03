import json
import re

from django.core.management.base import BaseCommand, CommandError

from cveFeed import openvas_scan

UUID = re.compile(r'^[0-9a-fA-F-]{36}$')


class Command(BaseCommand):
    help = ('Read what gvmd has for one OpenVAS task, the way the import reads it, and print the counts as JSON: the task status, the result '
            'count gvmd gives, the results read from the report (with and without a CVE), the hosts the report lists with their start and end, '
            'and which of them count as scanned. Read only: it imports nothing, marks no host and deletes nothing. Run it in the celery '
            'container (the one with gvmd\'s socket): `docker compose exec -T celery python3 manage.py openvas_task_report --run 12` (an OpenvasRun '
            'id, as in the activity line "OpenVAS run 12 ...") or `--task <GVM task id>`.')

    def add_arguments(self, parser):
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument('--run', type=int, help='the cvENGINE run id ("OpenVAS run 12")')
        target.add_argument('--task', help='the GVM task id')

    def handle(self, *args, **options):
        from cveFeed.models import OpenvasRun
        task_id, run = options.get('task'), None
        if options.get('run'):
            run = OpenvasRun.objects.filter(pk=options['run']).first()
            if run is None or not run.task_id:
                raise CommandError(f'no local OpenVAS run {options["run"]} with a GVM task')
            task_id = run.task_id
        if not UUID.match(task_id or ''):
            raise CommandError('the GVM task id is a UUID')
        try:
            with openvas_scan.session() as gmp:
                status = gmp.get_task(task_id)
                got = openvas_scan.task_results(gmp, status, task_id)
                page = gmp.get_results(filter_string=f'task_id={task_id} {openvas_scan.RESULT_FILTER} rows=10 first=1', details=True)
        except openvas_scan.OpenvasError as exc:
            raise CommandError(str(exc))
        task = status.find('./task')
        scanned = openvas_scan.scanned_addresses(None, status, got['items'], hosts=got['hosts'])
        out = {
            'task': task_id, 'name': openvas_scan._text(task, 'name'), 'status': openvas_scan._text(task, 'status'),
            'progress': openvas_scan._text(task, 'progress'), 'report': got['report_id'],
            'gvm_result_count': got['gvm_count'], 'results_read': len(got['items']) + got['unusable'],
            'report_result_count': got['count'], 'read_short_of_count': got['short'],
            'with_cve': sum(1 for i in got['items'] if i['cves']), 'without_cve': got['no_cve'], 'unusable': got['unusable'],
            'report_hosts': got['hosts'], 'host_minutes': openvas_scan.host_minutes(got['hosts']), 'scanned': sorted(scanned),
            # the first page of get_results, read as 1.3.2 read it (inside <results>) and as gvmd sends it (direct children): issue #394
            'get_results_first_page': {'read_as_in_1_3_2': len(page.findall('./results/result')), 'sent_by_gvmd': len(page.findall('result'))},
        }
        if run is not None:
            out['run'] = {'id': run.pk, 'status': run.status, 'hosts': run.hosts, 'summary': run.summary, 'error': run.error}
        self.stdout.write(json.dumps(out, indent=2, sort_keys=True, default=str))
