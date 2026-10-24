// "Add targets" dialog available on every page: paste or upload a list, choose how deep to look, go.
// Entries may be domains, IP addresses, CIDR blocks or ranges, separated by lines, commas or spaces.
const slug = document.body.dataset.slug;
// In the all-projects view ("_all") there is no one project to add to: every list needs a #Project line above it.
const ALL = slug === '_all';
const csrfInput = document.querySelector('[name=csrfmiddlewaretoken]');
let dialog = null;

const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

// Grouped format: an optional "##Organization" line, then "#Project" above each list ("# a comment" with a space is a comment).
// Anything else is a plain list for this project.
const isOrgFormat = (text) => text.split('\n').some((l) => /^\s*#\S/.test(l));
const countEntries = (text) =>
  isOrgFormat(text)
    ? countTokens(text.split('\n').filter((l) => !l.trim().startsWith('#')))
    : countTokens(text.split('\n'));
const projectCount = (text) => new Set(text.split('\n').map((l) => l.trim()).filter((l) => /^#[^#\s]/.test(l)).map((l) => l.slice(1).trim().toLowerCase())).size;
// Mirrors agentapi.services.normalize_target so the count matches what will be added: URLs become hosts.
const normalizeTarget = (token) => {
  let t = (token || '').trim().replace(/^["'<>`,;]+|["'<>`,;]+$/g, '');
  if (!t) return '';
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  if (!/^[0-9a-fA-F:.]+\/\d{1,3}$/.test(t)) {
    t = t.split(/[/?#]/)[0];
    t = t.slice(t.lastIndexOf('@') + 1);
    if (t.startsWith('[')) t = t.slice(1).split(']')[0];
    else if ((t.match(/:/g) || []).length === 1) t = t.replace(/:\d{1,5}$/, '');
  }
  t = t.toLowerCase().replace(/\.+$/, '').replace(/^\*\./, '');
  return t.replace(/^(\d{1,3}(\.\d{1,3}){3})\/32$/, '$1');
};
const stripLinks = (line) => line.replace(/\[[^\]]*\]\(([^)\s]*)\)/g, '$1');
const countTokens = (lines) => new Set(lines.map((l) => stripLinks(l.split('#')[0])).join(' ').split(/[,\s;]+/).map(normalizeTarget).filter(Boolean)).size;

function csrf() {
  const fromCookie = document.cookie.split('; ').find((c) => c.startsWith('csrftoken='));
  return csrfInput ? csrfInput.value : (fromCookie ? fromCookie.split('=')[1] : '');
}

function build() {
  const d = el('dialog', 'dlg', null, { 'aria-labelledby': 'dlg-title' });
  const form = el('form', 'dlg-body', null, { method: 'dialog' });
  const title = el('h2', '', 'Add targets', { id: 'dlg-title' });
  const lead = el('p', 'note', ALL
    ? 'You are viewing all projects, so say which project each list belongs to: put #Project above each list of domains, IP addresses, CIDR blocks or ranges (optionally ##Organization first; if it does not exist your current organization is used). Missing projects are created if you are an admin of the organization.'
    : 'Paste domains, IP addresses, CIDR blocks or ranges, one per line or separated by commas. To fill several projects at once, put #Project above each list (optionally ##Organization first; if it does not exist your current organization is used). Missing projects are created if you are an admin of the organization.');
  const area = el('textarea', 'dlg-area', null, { rows: '8', spellcheck: 'false', autocapitalize: 'none', 'aria-label': 'Targets',
    placeholder: 'example.com\n203.0.113.10\n10.0.0.0/28\n\nor, for several projects:\n##Acme\n#Web\nexample.com\n#Network\n10.0.0.0/28' });
  const tools = el('div', 'dlg-tools');
  const count = el('span', 'note', '0 targets');
  const file = el('input', '', null, { type: 'file', accept: '.txt,.csv,.list,text/plain', id: 'dlg-file', style: 'display:none' });
  const pick = el('label', 'btn ghost sm', 'Upload a file', { for: 'dlg-file', style: 'display:inline-flex;align-items:center;margin:0;cursor:pointer' });
  tools.append(count, el('span', 'grow'), pick, file);
  const mode = el('select', '', null, { 'aria-label': 'Discovery' });
  [['standard', 'Standard discovery (subdomains and web fingerprinting, safe modules only)'], ['deep', 'Deep discovery (everything: brute forcing, spidering, takes hours)'], ['passive', 'Passive discovery (public sources only, fast)'], ['none', 'Just add them, do not scan yet']]
    .forEach(([v, t]) => mode.append(Object.assign(el('option', '', t), { value: v })));
  const auth = el('input', '', null, { type: 'checkbox', id: 'dlg-auth' });
  const authWrap = el('label', 'check', null, { for: 'dlg-auth' });
  authWrap.append(auth, document.createTextNode('I am authorized to test these targets. Standard and deep discovery send traffic to them.'));
  const msg = el('div', 'msg', '', { role: 'status', style: 'display:none' });
  const out = el('div', 'dlg-out');
  const actions = el('div', 'actions');
  const cancel = el('button', 'btn ghost', 'Close', { type: 'button' });
  const go = el('button', 'btn', 'Add targets', { type: 'submit' });
  actions.append(el('span', 'grow'), cancel, go);
  form.append(title, lead, area, tools, el('div', 'field', null, { style: 'margin-top:12px' }), authWrap, msg, out, actions);
  form.children[4].append(mode);
  d.append(form);
  document.body.append(d);

  area.addEventListener('input', () => { const n = countEntries(area.value); count.textContent = `${n} target${n === 1 ? '' : 's'}${isOrgFormat(area.value) ? ` across ${projectCount(area.value)} project${projectCount(area.value) === 1 ? '' : 's'}` : ''}`; });
  file.addEventListener('change', () => {
    const f = file.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { area.value = (area.value ? `${area.value}\n` : '') + String(reader.result); area.dispatchEvent(new Event('input')); };
    reader.readAsText(f);
    file.value = '';
  });
  cancel.onclick = () => d.close();
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    msg.style.display = 'none'; out.textContent = '';
    if (!countEntries(area.value)) { msg.className = 'msg err'; msg.textContent = 'Paste at least one target.'; msg.style.display = 'block'; return; }
    if (ALL && !isOrgFormat(area.value)) { msg.className = 'msg err'; msg.textContent = 'Put #Project above each list, or switch to a project first.'; msg.style.display = 'block'; return; }
    if (mode.value !== 'none' && !auth.checked) { msg.className = 'msg err'; msg.textContent = 'Please confirm you are authorized to test these targets.'; msg.style.display = 'block'; return; }
    go.disabled = true;
    // Big pastes can take a while on a busy server: say what is happening and how long it has been going
    const n = countEntries(area.value);
    const started = Date.now();
    const working = () => {
      const secs = Math.round((Date.now() - started) / 1000);
      msg.className = 'msg busy';
      msg.textContent = `Checking ${n} target${n === 1 ? '' : 's'} for duplicates and adding the new ones${mode.value === 'none' ? '' : ', then queueing discovery'}...${secs >= 2 ? ` ${secs}s` : ''}`;
      msg.style.display = 'block';
    };
    working();
    const ticker = setInterval(working, 1000);
    go.textContent = 'Adding...';
    area.readOnly = true;
    try {
      const orgMode = isOrgFormat(area.value);
      const res = await fetch(orgMode ? '/api/v1/targets/bulk-org' : `/api/v1/projects/${encodeURIComponent(slug)}/targets/bulk`, {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf() },
        body: JSON.stringify({ text: area.value, discover: mode.value !== 'none', mode: mode.value === 'none' ? undefined : mode.value, current_project: orgMode && !ALL ? slug : undefined }),
      });
      const data = await res.json();
      clearInterval(ticker);
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      const existed = orgMode ? data.projects.reduce((n, p) => n + p.already_exists.length, 0) : data.already_exists.length;
      const bad = orgMode ? data.invalid.concat(...data.projects.map((p) => p.invalid)) : data.invalid;
      const parts = [`${data.created} added`];
      if (orgMode && data.projects_created) parts.push(`${data.projects_created} project${data.projects_created === 1 ? '' : 's'} created`);
      if (existed) parts.push(`${existed} already existed`);
      if (bad.length) parts.push(`${bad.length} not recognized`);
      if (data.discovery_started) parts.push(`${data.discovery_started} queued for discovery, in order`);
      if (data.mode_note) parts.push(data.mode_note);
      const failed = orgMode ? data.projects.filter((p) => p.error) : [];
      if (orgMode && data.organization_note) parts.push(data.organization_note);
      msg.className = `msg ${data.created && !failed.length ? 'ok' : 'err'}`;
      msg.textContent = parts.join(', ') + '.';
      msg.style.display = 'block';
      if (failed.length) {
        const list = el('ul', 'dlg-invalid');
        failed.forEach((p) => list.append(el('li', '', `${p.project}: ${p.error}`)));
        out.append(el('p', 'note', 'Not added:'), list);
      }
      if (bad.length) {
        const list = el('ul', 'dlg-invalid');
        bad.slice(0, 20).forEach((i) => list.append(el('li', '', `${i.value}: ${i.error}`)));
        out.append(el('p', 'note', 'Not recognized:'), list);
      }
      if (data.scan_ids.length) {
        const watch = el('a', 'btn sm', 'Watch it live', { href: `/cve/?follow=${data.scan_ids[0]}`, style: 'display:inline-flex;align-items:center;text-decoration:none;margin-top:10px' });
        out.append(watch);
      }
      if (data.created) { area.value = ''; area.dispatchEvent(new Event('input')); document.dispatchEvent(new CustomEvent('cve:targets-added', { detail: data })); }
    } catch (err) {
      msg.className = 'msg err'; msg.textContent = err.message; msg.style.display = 'block';
    }
    clearInterval(ticker);
    go.textContent = 'Add targets';
    area.readOnly = false;
    go.disabled = false;
  });
  d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
  return d;
}

export function openAddTargets() {
  if (!slug) return;
  if (!dialog) dialog = build();
  dialog.showModal();
  dialog.querySelector('textarea').focus();
}

document.querySelectorAll('[data-add-targets]').forEach((b) => b.addEventListener('click', openAddTargets));
window.CVE = { ...(window.CVE || {}), openAddTargets };
