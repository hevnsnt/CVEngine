"""What the finding backfill commands (dedupe_findings, fold_alias_findings, close_fixed_findings) share: the projects to work on and a
line per project. Each command is a dry run unless --apply, so a person reads the counts before anything changes."""


def add_arguments(parser):
    parser.add_argument('--apply', action='store_true', help='Change the findings. Without it the command only counts.')
    parser.add_argument('--project', action='append', default=[], help='Project slug (repeatable). Every project when left out.')


def projects(opts):
    from dashboard.models import Project
    qs = Project.objects.all().order_by('id')
    if opts.get('project'):
        qs = qs.filter(slug__in=opts['project'])
    return list(qs)


def line(project, counts):
    return f'{project.slug}: ' + ', '.join(f'{key} {value}' for key, value in counts.items())
