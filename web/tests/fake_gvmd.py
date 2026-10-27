"""A fake gvmd for tests: a unix-socket server that speaks GMP (the Greenbone Management Protocol) in the XML formats gvmd 22.x documents, so the
real python-gvm client runs against it unchanged (framing, version negotiation, authentication, status codes and all).

It is a fixture, not a mock of cvENGINE's own code: the requests it answers are the ones python-gvm sends, and the answers are shaped like the
GMP reference's get_version, authenticate, get_feeds, get_configs, get_scanners, get_port_lists, get_targets, create_target, create_task,
start_task, get_tasks (status values New, Requested, Queued, Running, Stop Requested, Stopped, Interrupted, Done), get_results (nvt oid, refs, qod,
severity, threat, port, host with hostname) and get_reports. What it cannot prove is that a real gvmd answers the same way: see docs/OPENVAS.md.
"""
import base64
import itertools
import os
import socket
import tempfile
import threading
import uuid
from xml.sax.saxutils import escape

from lxml import etree

FULL_AND_FAST = 'daba56c8-73ec-11df-a475-002264764cea'
OPENVAS_SCANNER = '08b69003-5fc2-4037-a479-93b440211c73'
IANA_TCP = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
FAMILIES = ['Denial of Service', 'Brute force attacks', 'Web application abuses', 'General', 'Product detection', 'Gain a shell remotely',
            'Buffer overflow', 'Port scanners']
FEED_TYPES = ('NVT', 'CERT', 'SCAP', 'GVMD_DATA')


def ok(tag, body='', status='200', text='OK', **attrs):
    extra = ''.join(f' {k}="{escape(str(v))}"' for k, v in attrs.items())
    return f'<{tag} status="{status}" status_text="{escape(text)}"{extra}>{body}</{tag}>'


class FakeGvmd:
    """``with FakeGvmd() as gvmd: ... gvmd.path``. Tests drive it through the attributes below and read ``requests`` (the commands received,
    never the password) and ``connections``."""

    def __init__(self, user='cvengine', password='fake-gmp-password-not-real', nvts=95000, syncing=False, feeds=FEED_TYPES, version='22.7'):
        self.user, self.password, self.version = user, password, version
        self.users = {user: password}  # name -> password: a test adds more
        self.nvts, self.syncing, self.feeds = nvts, syncing, set(feeds)
        self.tmp = tempfile.mkdtemp(prefix='fake-gvmd-')
        self.path = os.path.join(self.tmp, 'gvmd.sock')
        self.requests, self.connections = [], 0
        self.configs = {FULL_AND_FAST: {'name': 'Full and fast', 'families': {f: {'count': 40, 'growing': True} for f in FAMILIES}, 'safe_checks': 'yes'}}
        self.targets, self.tasks, self.results, self.report_hosts = {}, {}, {}, {}  # results: task id -> [result xml]
        self.fail = {}  # command -> (status, text): make one command fail
        self.report_has_hosts = True
        self.extra_report_hosts = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._ids = itertools.count(1)

    # --- lifecycle
    def __enter__(self):
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(self.path)
        self.server.listen(8)
        self.server.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self.thread.join(timeout=3)
        self.server.close()
        for name in os.listdir(self.tmp):
            os.unlink(os.path.join(self.tmp, name))
        os.rmdir(self.tmp)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            with self._lock:
                self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.settimeout(5)
        buffer = b''
        authenticated = False
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except (socket.timeout, OSError):
                    return
                if not chunk:
                    return
                buffer += chunk
                try:
                    root = etree.fromstring(buffer)
                except etree.XMLSyntaxError:
                    continue  # the request is not complete yet
                buffer = b''
                reply, authenticated = self._answer(root, authenticated)
                conn.sendall(reply.encode())
        finally:
            conn.close()

    # --- state the tests set up
    def new_id(self):
        return str(uuid.UUID(int=next(self._ids) + 0xAB0000))

    def set_status(self, task_id, status, progress=0):
        self.tasks[task_id]['status'], self.tasks[task_id]['progress'] = status, progress

    def add_result(self, task_id, host, port, oid, name, severity, qod, cves=(), description='Detection result.', hostname='', threat=None,
                   qod_type='remote_banner', tags=None, urls=()):
        refs = ''.join(f'<ref type="cve" id="{c}"/>' for c in cves) + ''.join(f'<ref type="url" id="{escape(u)}"/>' for u in urls)
        tags = tags if tags is not None else (f'cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:P/A:P|summary=The product {name} is affected.|'
                                              'insight=A flaw in request handling.|affected=Versions before 2.4.51|solution_type=VendorFix')
        threat = threat or ('Critical' if severity >= 9 else 'High' if severity >= 7 else 'Medium' if severity >= 4 else 'Low' if severity > 0 else 'Log')
        host_el = f'<host>{host}<asset asset_id="{self.new_id()}"/><hostname>{escape(hostname)}</hostname></host>'
        xml = (f'<result id="{self.new_id()}"><name>{escape(name)}</name><owner><name>{self.user}</name></owner>'
               f'<modification_time>2026-10-27T10:00:00Z</modification_time><comment/><creation_time>2026-10-27T10:00:00Z</creation_time>'
               f'{host_el}<port>{port}</port>'
               f'<nvt oid="{oid}"><type>nvt</type><name>{escape(name)}</name><family>Web application abuses</family><cvss_base>{severity}</cvss_base>'
               f'<severities score="{severity}"><severity type="cvss_base_v2"><score>{severity}</score></severity></severities>'
               f'<tags>{escape(tags)}</tags><solution type="VendorFix">Update to the fixed release.</solution><refs>{refs}</refs></nvt>'
               f'<scan_nvt_version>2026-10-20T09:00:00Z</scan_nvt_version><threat>{threat}</threat><severity>{severity}</severity>'
               f'<qod><value>{qod}</value><type>{qod_type}</type></qod><description>{escape(description)}</description></result>')
        self.results.setdefault(task_id, []).append(xml)
        self.report_hosts.setdefault(task_id, set()).add(host)

    def sent(self, tag):
        return [r for r in self.requests if r.tag == tag]

    # --- GMP
    def _answer(self, root, authenticated):
        tag = root.tag
        if tag != 'authenticate':
            self.requests.append(root)
        if tag in self.fail:
            status, text = self.fail[tag]
            return f'<{tag}_response status="{status}" status_text="{escape(text)}"/>', authenticated
        if tag == 'get_version':
            return ok('get_version_response', f'<version>{self.version}</version>'), authenticated
        if tag == 'authenticate':
            creds = root.find('credentials')
            if creds is not None and self.users.get(creds.findtext('username')) == creds.findtext('password') and creds.findtext('password'):
                return ok('authenticate_response', '<role>User</role><timezone>UTC</timezone><severity>nist</severity>'), True
            return '<authenticate_response status="400" status_text="Authentication failed"/>', False
        if not authenticated:
            return f'<{tag}_response status="401" status_text="Only command GET_VERSION is allowed before AUTHENTICATE"/>', False
        handler = getattr(self, f'cmd_{tag}', None)
        if handler is None:
            return f'<{tag}_response status="400" status_text="Bogus command name"/>', authenticated
        return handler(root), authenticated

    def cmd_get_users(self, root):
        wanted = (root.get('filter') or '').replace('name=', '')
        return ok('get_users_response', ''.join(f'<user id="{uuid.uuid5(uuid.NAMESPACE_DNS, n)}"><name>{escape(n)}</name><role id="x"><name>Admin</name></role></user>'
                                                for n in self.users if not wanted or wanted == n))

    def cmd_modify_user(self, root):
        for name in self.users:
            if str(uuid.uuid5(uuid.NAMESPACE_DNS, name)) == root.get('user_id'):
                self.users[name] = root.findtext('password')
                return ok('modify_user_response')
        return '<modify_user_response status="404" status_text="Failed to find user"/>'

    def cmd_get_feeds(self, root):
        body = ''
        for kind in FEED_TYPES:
            if kind not in self.feeds:
                continue
            syncing = '<currently_syncing><timestamp>2026-10-27T12:00:00Z</timestamp></currently_syncing>' if self.syncing and kind == 'NVT' else ''
            body += (f'<feed><type>{kind}</type><name>Greenbone Community Feed</name><version>202610270500</version>'
                     f'<description>The feed.</description>{syncing}</feed>')
        return ok('get_feeds_response', body)

    def _config_xml(self, config_id, config, details):
        selected = {f: v for f, v in config['families'].items()}
        families = ''.join(f'<family><name>{escape(f)}</name><nvt_count>{v["count"]}</nvt_count><max_nvt_count>40</max_nvt_count>'
                           f'<growing>{int(v["growing"])}</growing></family>' for f, v in selected.items())
        prefs = (f'<preference><nvt oid=""><name/></nvt><hr_name>Safe checks</hr_name><name>safe_checks</name><id/><type>checkbox</type>'
                 f'<value>{config["safe_checks"]}</value><alt>yes</alt><default>yes</default></preference>')
        total = self.nvts if config_id == FULL_AND_FAST else sum(v['count'] for v in selected.values())
        return (f'<config id="{config_id}"><owner><name/></owner><name>{escape(config["name"])}</name><comment/>'
                f'<creation_time>2026-10-01T00:00:00Z</creation_time><modification_time>2026-10-01T00:00:00Z</modification_time>'
                f'<writable>{0 if config_id == FULL_AND_FAST else 1}</writable><in_use>0</in_use>'
                f'<family_count>{len(selected)}<growing>1</growing></family_count><nvt_count>{total}<growing>1</growing></nvt_count>'
                f'<type>0</type><usage_type>scan</usage_type><families>{families}</families><preferences>{prefs}</preferences></config>')

    def cmd_get_configs(self, root):
        wanted = root.get('config_id')
        body = ''.join(self._config_xml(i, c, True) for i, c in self.configs.items() if not wanted or wanted == i)
        if wanted and not body:
            return '<get_configs_response status="404" status_text="Failed to find config"/>'
        return ok('get_configs_response', body)

    def cmd_create_config(self, root):
        source = self.configs.get(root.findtext('copy'))
        if source is None:
            return '<create_config_response status="404" status_text="Failed to find config"/>'
        new = self.new_id()
        self.configs[new] = {'name': root.findtext('name'), 'families': {f: dict(v) for f, v in source['families'].items()}, 'safe_checks': source['safe_checks']}
        return ok('create_config_response', status='201', text='OK, resource created', id=new)

    def cmd_get_nvt_families(self, root):
        return ok('get_nvt_families_response', '<families>' + ''.join(f'<family><name>{escape(f)}</name><max_nvt_count>40</max_nvt_count></family>' for f in FAMILIES) + '</families>')

    def cmd_modify_config(self, root):
        config = self.configs[root.get('config_id')]
        selection = root.find('family_selection')
        if selection is not None:
            chosen = {f.findtext('name'): f for f in selection.findall('family')}
            config['families'] = {name: {'count': 40 if f.findtext('all') == '1' else 5, 'growing': f.findtext('growing') == '1'} for name, f in chosen.items()}
        pref = root.find('preference')
        if pref is not None and pref.findtext('name') == 'safe_checks':
            config['safe_checks'] = base64.b64decode(pref.findtext('value') or '').decode()  # GMP carries preference values base64 encoded
        return ok('modify_config_response')

    def cmd_get_scanners(self, root):
        return ok('get_scanners_response', f'<scanner id="{OPENVAS_SCANNER}"><name>OpenVAS Default</name><type>2</type></scanner>'
                  '<scanner id="6acd0832-df90-11e4-b9d5-28d24461215b"><name>CVE</name><type>3</type></scanner>')

    def cmd_get_port_lists(self, root):
        return ok('get_port_lists_response', f'<port_list id="{IANA_TCP}"><name>All IANA assigned TCP</name></port_list>'
                  '<port_list id="4a4717fe-57d2-11e1-9a26-406186ea4fc5"><name>All IANA assigned TCP and UDP</name></port_list>')

    def cmd_get_targets(self, root):
        wanted = (root.get('filter') or '').replace('uuid=', '')
        return ok('get_targets_response', ''.join(f'<target id="{i}"><name>{escape(t["name"])}</name><hosts>{escape(t["hosts"])}</hosts></target>'
                                                 for i, t in self.targets.items() if not wanted or wanted == i))

    def cmd_create_target(self, root):
        new = self.new_id()
        self.targets[new] = {'name': root.findtext('name'), 'hosts': root.findtext('hosts'), 'port_list': root.find('port_list').get('id')}
        return ok('create_target_response', status='201', text='OK, resource created', id=new)

    def cmd_delete_target(self, root):
        self.targets.pop(root.get('target_id'), None)
        return ok('delete_target_response')

    def cmd_create_task(self, root):
        new = self.new_id()
        prefs = {p.findtext('scanner_name'): p.findtext('value') for p in root.findall('./preferences/preference')}
        self.tasks[new] = {'name': root.findtext('name'), 'config': root.find('config').get('id'), 'target': root.find('target').get('id'),
                           'scanner': root.find('scanner').get('id'), 'status': 'New', 'progress': -1, 'prefs': prefs, 'report': self.new_id()}
        return ok('create_task_response', status='201', text='OK, resource created', id=new)

    def cmd_start_task(self, root):
        task = self.tasks[root.get('task_id')]
        task['status'], task['progress'] = 'Requested', 0
        return ok('start_task_response', f'<report_id>{task["report"]}</report_id>', status='202', text='OK, request submitted')

    def cmd_stop_task(self, root):
        self.tasks[root.get('task_id')]['status'] = 'Stop Requested'
        return ok('stop_task_response', status='202', text='OK, request submitted')

    def cmd_delete_task(self, root):
        self.tasks.pop(root.get('task_id'), None)
        return ok('delete_task_response')

    def cmd_get_tasks(self, root):
        task_id = root.get('task_id')
        if task_id not in self.tasks:
            return f'<get_tasks_response status="404" status_text="Failed to find task \'{task_id}\'"/>'
        task = self.tasks[task_id]
        report = f'<last_report><report id="{task["report"]}"><timestamp>2026-10-27T12:30:00Z</timestamp></report></last_report>' if task['status'] == 'Done' else ''
        return ok('get_tasks_response', f'<task id="{task_id}"><name>{escape(task["name"])}</name><status>{task["status"]}</status>'
                  f'<progress>{task["progress"]}</progress>{report}</task>')

    def cmd_get_results(self, root):
        task_id = (root.get('filter') or '').split('task_id=')[1].split()[0] if 'task_id=' in (root.get('filter') or '') else root.get('task_id')
        words = dict(w.split('=', 1) for w in (root.get('filter') or '').split() if '=' in w)
        rows, first = int(words.get('rows', 100)), int(words.get('first', 1))
        every = self.results.get(task_id, [])
        page = every[first - 1:first - 1 + rows]
        return ok('get_results_response', f'<results start="{first}" max="{rows}">{"".join(page)}</results><result_count>{len(every)}</result_count>')

    def cmd_get_reports(self, root):
        task = next((t for t in self.tasks.values() if t['report'] == root.get('report_id')), None)
        task_id = next((i for i, t in self.tasks.items() if t is task), None)
        hosts = ''.join(f'<host><ip>{h}</ip><asset asset_id="{self.new_id()}"/><start>2026-10-27T12:00:00Z</start><end>2026-10-27T12:30:00Z</end></host>'
                        for h in sorted(self.report_hosts.get(task_id, set()))) if self.report_has_hosts else ''
        extra = ''.join(f'<host><ip>{h}</ip><start>x</start><end>x</end></host>' for h in sorted(self.extra_report_hosts))
        return ok('get_reports_response', f'<report id="{root.get("report_id")}"><report id="{root.get("report_id")}"><scan_run_status>Done</scan_run_status>'
                  f'<hosts><count>{len(self.report_hosts.get(task_id, set()))}</count></hosts>{hosts}{extra}</report></report>')
