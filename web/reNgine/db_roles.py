"""Which PostgreSQL role a process connects as, and the least privilege role the application runs as.

Two roles share the database:

* the OWNER role (``POSTGRES_USER``, the role the database image created; a superuser on a stock install) owns every table. It is used only by
  the migrations, ``createsuperuser``, the test runner, ``showmigrations`` and ``dbshell`` (``OWNER_COMMANDS``), by any process started with
  ``CVENGINE_DB_ROLE=owner``, and by the backups and the database image's own tools, which run inside the db container.
* the APP role (``CVENGINE_DB_APP_USER``, default ``cvengine_app``, password ``CVENGINE_DB_APP_PASSWORD``) is what web, celery, celery-beat and
  every management command they run use. It is ``NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`` and holds only what the code
  needs at run time (``grant_statements``): CONNECT, USAGE on the schema, SELECT INSERT UPDATE DELETE on every table, USAGE SELECT UPDATE on
  every sequence, EXECUTE on the schema's functions, and ``pg_maintain`` (PostgreSQL 17 or newer) because ``cveFeed.db_stats`` runs ``ANALYZE``
  from a Celery task. So an SQL injection or a bug in the application can no longer run ``COPY ... TO PROGRAM``, read or write server files,
  create roles, ``ALTER SYSTEM`` or drop a table.

Fallback, so an update never locks anyone out: with ``CVENGINE_DB_APP_USER`` or ``CVENGINE_DB_APP_PASSWORD`` empty the owner role is used, as
before this existed. Every ``migrate`` that runs as the owner creates or updates the app role and grants it (``ensure``, called from the
``post_migrate`` signal and by ``manage.py db_app_role ensure``), idempotently. The container entrypoints then ``choose``: when the app role
cannot log in but the owner can (the role was never created, its password differs) the container keeps the owner role, says so in its log and
writes that choice to ``STATE_FILE``, which every later process of the same container (``docker compose exec``) reads through ``resolve``.

This module imports nothing from Django at import time: settings.py calls ``resolve`` while the settings are being built.
"""
import os
import re
import time

APP_USER_DEFAULT = 'cvengine_app'
# written by the entrypoints (``choose``); read by every later process of the container. CVENGINE_DB_ROLE_STATE moves it (the tests do).
STATE_FILE = '/tmp/cvengine-db-role'
# The management commands that need the owner role: they change the schema (migrate), are run around a migration by the update scripts
# (showmigrations, db_app_role) or by an administrator for maintenance (createsuperuser, dbshell), or create and drop test databases (test).
OWNER_COMMANDS = frozenset({'migrate', 'showmigrations', 'createsuperuser', 'test', 'db_app_role', 'dbshell'})
# ``migrate --check`` and ``migrate --plan`` only read django_migrations, which the app role may: the workers' wait loop runs it as the app role,
# which also proves the role can log in before they start.
READ_ONLY_FLAGS = frozenset({'--check', '--plan'})
ROLE_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]{0,62}$')
ADVISORY_LOCK = 21860090  # one ``ensure`` at a time (the web entrypoint and an update's migrate can overlap)
SCRAM = re.compile(r'^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$')
TABLE_PRIVILEGES = 'SELECT, INSERT, UPDATE, DELETE'
SEQUENCE_PRIVILEGES = 'USAGE, SELECT, UPDATE'
ROLE_ATTRIBUTES = 'LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT'
MAINTAIN_SINCE = 170000  # pg_maintain is a PostgreSQL 17 role


class RoleError(Exception):
    """The app role could not be created or granted; the application keeps the owner role."""


def ident(name):
    """``name`` as a quoted SQL identifier."""
    return '"' + str(name).replace('"', '""') + '"'


def app_user(environ):
    """The app role's name: ``CVENGINE_DB_APP_USER`` when it is set (empty means: no app role, use the owner), else ``cvengine_app``."""
    value = environ.get('CVENGINE_DB_APP_USER')
    return APP_USER_DEFAULT if value is None else value.strip()


def command_of(argv):
    """The management command of ``manage.py <command>`` (``django-admin`` too), else '' (gunicorn, celery, a script)."""
    argv = list(argv or [])
    if len(argv) >= 2 and os.path.basename(str(argv[0])) in ('manage.py', 'django-admin', 'django-admin.py'):
        return str(argv[1])
    return ''


def wants_owner(environ, argv):
    """Whether this process must use the owner role: ``CVENGINE_DB_ROLE=owner`` says so (``app`` says no), else the command decides."""
    forced = (environ.get('CVENGINE_DB_ROLE') or '').strip().lower()
    if forced in ('owner', 'app'):
        return forced == 'owner'
    command = command_of(argv)
    if command not in OWNER_COMMANDS:
        return False
    return not (command == 'migrate' and READ_ONLY_FLAGS.intersection(argv))


def read_state(path=None):
    """``(role, reason)`` the container's entrypoint chose, or ``(None, '')`` when it wrote none."""
    try:
        with open(path or os.environ.get('CVENGINE_DB_ROLE_STATE') or STATE_FILE, encoding='utf-8') as handle:
            text = handle.read(1000).strip()
    except OSError:
        return None, ''
    role, _, reason = text.partition(' ')
    return (role, reason) if role in ('app', 'owner') else (None, '')


def secret(environ, name):
    """``NAME`` from the environment, else the contents of the file ``NAME_FILE`` names (a Docker secret), else ''."""
    value = environ.get(name)
    if value:
        return value
    path = environ.get(f'{name}_FILE')
    if path:
        try:
            with open(path, encoding='utf-8') as handle:
                return handle.read().strip()
        except OSError:
            return ''
    return ''


def resolve(environ=None, argv=None, state_file: 'str | None' = ''):
    """``{role, user, password, reason, app_user}``: the credentials this process uses. ``role`` is ``app`` or ``owner``."""
    environ = os.environ if environ is None else environ
    if state_file == '':  # the default: where the entrypoint writes it
        state_file = environ.get('CVENGINE_DB_ROLE_STATE') or STATE_FILE
    owner = {'user': environ.get('POSTGRES_USER', ''), 'password': secret(environ, 'POSTGRES_PASSWORD')}
    name = app_user(environ)
    password = secret(environ, 'CVENGINE_DB_APP_PASSWORD')

    def use_owner(reason):
        return {'role': 'owner', **owner, 'reason': reason, 'app_user': name}

    if not name:
        return use_owner('CVENGINE_DB_APP_USER is empty')
    if not ROLE_NAME.match(name):
        return use_owner(f'CVENGINE_DB_APP_USER {name!r} is not a plain role name (letters, digits and _)')
    if name == owner['user']:
        return use_owner('CVENGINE_DB_APP_USER is the owner role itself')
    if not password:
        return use_owner('CVENGINE_DB_APP_PASSWORD is empty')
    if wants_owner(environ, argv):
        return use_owner('migrations and maintenance use the owner role')
    if not (environ.get('CVENGINE_DB_ROLE') or '').strip() and state_file:
        chosen, why = read_state(state_file)
        if chosen == 'owner':
            return use_owner(why or 'the container started on the owner role')
    return {'role': 'app', 'user': name, 'password': password, 'reason': '', 'app_user': name}


# --- the SQL ---------------------------------------------------------------------------------------------------------------------------------

def role_statement(app, verifier, exists):
    """CREATE (or, when it exists, ALTER) the app role with its attributes and password. ``verifier`` is a SCRAM verifier, never the password,
    so the statement in a log or ``pg_stat_statements`` does not reveal it."""
    if not ROLE_NAME.match(app):
        raise RoleError(f'{app!r} is not a plain role name')
    if not SCRAM.match(verifier or ''):
        raise RoleError('the password verifier is not a SCRAM-SHA-256 verifier')
    return f"{'ALTER' if exists else 'CREATE'} ROLE {ident(app)} WITH {ROLE_ATTRIBUTES} PASSWORD '{verifier}'"


def grant_statements(owner, app, database, schema='public', maintain=True):
    """Every GRANT the app role needs, in order; each one is idempotent. ``ALTER DEFAULT PRIVILEGES FOR ROLE <owner>`` covers the tables and
    sequences later migrations create, and ``ensure`` runs these again after every migrate anyway."""
    for name in (owner, app):
        if not ROLE_NAME.match(name or ''):
            raise RoleError(f'{name!r} is not a plain role name')
    o, a, s = ident(owner), ident(app), ident(schema)
    statements = [
        f'GRANT CONNECT ON DATABASE {ident(database)} TO {a}',
        f'GRANT USAGE ON SCHEMA {s} TO {a}',
        f'GRANT {TABLE_PRIVILEGES} ON ALL TABLES IN SCHEMA {s} TO {a}',
        f'GRANT {SEQUENCE_PRIVILEGES} ON ALL SEQUENCES IN SCHEMA {s} TO {a}',
        f'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {s} TO {a}',
        f'ALTER DEFAULT PRIVILEGES FOR ROLE {o} IN SCHEMA {s} GRANT {TABLE_PRIVILEGES} ON TABLES TO {a}',
        f'ALTER DEFAULT PRIVILEGES FOR ROLE {o} IN SCHEMA {s} GRANT {SEQUENCE_PRIVILEGES} ON SEQUENCES TO {a}',
        f'ALTER DEFAULT PRIVILEGES FOR ROLE {o} IN SCHEMA {s} GRANT EXECUTE ON FUNCTIONS TO {a}',
    ]
    if maintain:
        statements.append(f'GRANT pg_maintain TO {a}')
    return statements


def scram_verifier(raw_connection, password, user):
    """The SCRAM-SHA-256 verifier of ``password`` for ``user``, computed by libpq on the client (the password itself is never sent as SQL)."""
    try:
        from psycopg2.extensions import encrypt_password
        verifier = encrypt_password(password, user, raw_connection, 'scram-sha-256')
    except ImportError:  # psycopg 3
        verifier = raw_connection.pgconn.encrypt_password(password.encode(), user.encode(), b'scram-sha-256')
    return verifier.decode() if isinstance(verifier, bytes) else verifier


def ensure(connection, app, password, *, schema='public', log=None):
    """Create or update the app role and grant it, through ``connection`` (Django's, connected as the owner). Idempotent; one transaction, so a
    failure leaves the role and its grants as they were. Returns ``{created, maintain, owner}``; raises RoleError when it cannot."""
    from django.db import DatabaseError, transaction

    log = log or (lambda message: None)
    if not ROLE_NAME.match(app or ''):
        raise RoleError(f'{app!r} is not a plain role name')
    if not password:
        raise RoleError('CVENGINE_DB_APP_PASSWORD is empty')
    try:
        with transaction.atomic(using=connection.alias), connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', [ADVISORY_LOCK])
            cursor.execute("SELECT current_user, current_database(), current_setting('server_version_num')::int, r.rolsuper, r.rolcreaterole "
                           'FROM pg_roles r WHERE r.rolname = current_user')
            owner, database, version, superuser, createrole = cursor.fetchone()
            if owner == app:
                raise RoleError(f'connected as {app} itself, not as the owner role')
            if not (superuser or createrole):
                raise RoleError(f'the owner role {owner} may not create roles (it needs SUPERUSER or CREATEROLE)')
            cursor.execute('SELECT rolsuper FROM pg_roles WHERE rolname = %s', [app])
            row = cursor.fetchone()
            if row and row[0] and not superuser:
                raise RoleError(f'{app} is a superuser and {owner} is not, so it cannot be made an ordinary role')
            connection.ensure_connection()
            cursor.execute(role_statement(app, scram_verifier(connection.connection, password, app), exists=bool(row)))
            # the app role must not inherit the owner's rights through a membership somebody added by hand
            cursor.execute('SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member '
                           'WHERE r.rolname = %s AND u.rolname = %s', [owner, app])
            if cursor.fetchone():
                cursor.execute(f'REVOKE {ident(owner)} FROM {ident(app)}')
            for statement in grant_statements(owner, app, database, schema, maintain=False):
                cursor.execute(statement)
            maintain = False
            if version >= MAINTAIN_SINCE:
                try:
                    with transaction.atomic(using=connection.alias):
                        cursor.execute(grant_statements(owner, app, database, schema, maintain=True)[-1])
                    maintain = True
                except DatabaseError as exc:
                    log(f'could not grant pg_maintain to {app} ({exc}); the statistics refresh (cveFeed.db_stats) skips the tables until it is')
            else:
                log(f'PostgreSQL {version} has no pg_maintain: the statistics refresh (cveFeed.db_stats) skips the tables while the app role runs it')
    except DatabaseError as exc:
        raise RoleError(str(exc).strip()) from exc
    log(f"the database role {app} is {'created' if not row else 'up to date'} and granted ({owner} stays the owner)")
    return {'created': not row, 'maintain': maintain, 'owner': owner}


def ensure_after_migrate(using='default', log=None, warn=None):
    """The ``post_migrate`` step: when this process is the owner and an app role is configured, create or update it. Never raises: a migration
    must not fail for it, and the entrypoints keep the owner role when the app role cannot log in (``choose``)."""
    import logging

    from django.db import connections

    logger = logging.getLogger(__name__)
    say = log or logger.info
    from django.conf import settings
    name, password = app_user(os.environ), secret(os.environ, 'CVENGINE_DB_APP_PASSWORD')
    if getattr(settings, 'DATABASE_ROLE', 'owner') != 'owner' or not name or not password:
        return None
    if name == os.environ.get('POSTGRES_USER') or not ROLE_NAME.match(name):
        return None
    try:
        return ensure(connections[using], name, password, log=say)
    except RoleError as exc:
        message = f'db_app_role: could not create or grant the role {name} ({exc}); the application keeps the owner role'
        (warn or logger.warning)(message)
        return None


# --- the entrypoints' choice --------------------------------------------------------------------------------------------------------------------

def _connect(environ, user, password, timeout=5):
    import psycopg2
    return psycopg2.connect(dbname=environ.get('POSTGRES_DB', ''), user=user, password=password, host=environ.get('POSTGRES_HOST', ''),
                            port=environ.get('POSTGRES_PORT') or None, connect_timeout=timeout, application_name='cvengine-db-role-check')


def choose(environ=None, *, wait=0, connect=None, sleep=time.sleep, clock=time.monotonic):
    """``(role, reason)`` a container should run as: ``app`` when the app role logs in, ``owner`` when it is not configured or cannot log in
    while the owner can. ``wait`` seconds are given to a starting web service to create the role first. When the database answers neither
    role the answer is ``app`` (as configured): the entrypoint's own wait loop then waits for the database, as it always did."""
    environ = os.environ if environ is None else environ
    connect = connect or _connect
    runtime = resolve(environ, argv=['manage.py', 'runserver'], state_file=None)
    if runtime['role'] == 'owner':
        return 'owner', runtime['reason']
    deadline = clock() + max(0, wait)
    while True:
        try:
            connect(environ, runtime['user'], runtime['password']).close()
            return 'app', ''
        except Exception as app_error:  # noqa: BLE001 - any failure: ask whether the owner gets in
            reason = str(app_error).strip().splitlines()[0] if str(app_error).strip() else type(app_error).__name__
        try:
            connect(environ, environ.get('POSTGRES_USER', ''), secret(environ, 'POSTGRES_PASSWORD')).close()
            owner_in = True
        except Exception:  # noqa: BLE001
            owner_in = False
        if clock() >= deadline:
            if owner_in:
                return 'owner', f"the role {runtime['user']} cannot log in yet ({reason})"
            return 'app', ''
        sleep(3)


def write_state(role, reason, path=None):
    with open(path or os.environ.get('CVENGINE_DB_ROLE_STATE') or STATE_FILE, 'w', encoding='utf-8') as handle:
        handle.write(f'{role} {reason}'.strip() + '\n')
