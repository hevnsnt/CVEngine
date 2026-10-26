// "Add targets" dialog available on every page: paste or upload a list, choose how deep to look, go.
// Entries may be domains, IP addresses, CIDR blocks or ranges, separated by lines, commas or spaces.
const slug = document.body.dataset.slug;
// In the all-projects view ("_all") there is no one project to add to: every list needs a #Project line above it.
const ALL = slug === '_all';
const csrfInput = document.querySelector('[name=csrfmiddlewaretoken]');
let dialog = null;

// Where the targets go: an organization and a project, filled in with where the user is now. The page ships its project list
// (with each project's organization) for the switchers; the dialog reuses it.
const readJson = (id) => {
  const node = document.getElementById(id);
  try { return node ? JSON.parse(node.textContent) : []; } catch (_) { return []; }
};
const PROJECTS = readJson('switch-projects');
const orgOf = (p) => p.org_slug || '';
const ORGS = PROJECTS.reduce((list, p) => (list.some((o) => o.slug === orgOf(p)) ? list : list.concat({ slug: orgOf(p), name: p.org_name || 'No organization' })), []);
const here = PROJECTS.find((p) => p.slug === slug);

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
  if (t.length > 1 && t.startsWith('-')) { const rest = normalizeTarget(t.slice(1)); return rest && !rest.startsWith('-') ? `-${rest}` : ''; }
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
const tokensOf = (lines) => new Set(lines.map((l) => stripLinks(l.split('#')[0])).join(' ').split(/[,\s;]+/).map(normalizeTarget).filter(Boolean));
const countTokens = (lines) => [...tokensOf(lines)].filter((t) => !t.startsWith('-')).length;
// "-example.com" lines exclude a domain (and everything under it) instead of adding a target
const countExclusions = (text) => [...tokensOf(text.split('\n').filter((l) => !isOrgFormat(text) || !l.trim().startsWith('#')))].filter((t) => t.startsWith('-')).length;
const countLabel = (text) => {
  const n = countEntries(text), x = countExclusions(text);
  return `${n} target${n === 1 ? '' : 's'}${x ? `, ${x} exclusion${x === 1 ? '' : 's'}` : ''}${isOrgFormat(text) ? ` across ${projectCount(text)} project${projectCount(text) === 1 ? '' : 's'}` : ''}`;
};

function csrf() {
  const fromCookie = document.cookie.split('; ').find((c) => c.startsWith('csrftoken='));
  return csrfInput ? csrfInput.value : (fromCookie ? fromCookie.split('=')[1] : '');
}

function build() {
  const d = el('dialog', 'dlg', null, { 'aria-labelledby': 'dlg-title' });
  const form = el('form', 'dlg-body', null, { method: 'dialog' });
  const title = el('h2', '', 'Add targets', { id: 'dlg-title' });
  const lead = el('p', 'note', ALL
    ? 'You are viewing all projects, so say which project each list belongs to: put #Project above each list of domains, IP addresses, CIDR blocks or ranges (optionally ##Organization first; if it does not exist your current organization is used). Missing projects are created if you are an admin of the organization. Start a line with - to exclude a domain and everything under it for the whole organization (for example -example.com): its hosts and targets are removed and never scanned again.'
    : 'Paste domains, IP addresses, CIDR blocks or ranges, one per line or separated by commas. To fill several projects at once, put #Project above each list (optionally ##Organization first; if it does not exist your current organization is used). Missing projects are created if you are an admin of the organization. Start a line with - to exclude a domain and everything under it for the whole organization (for example -example.com): its hosts and targets are removed and never scanned again.');
  const orgSel = el('select', '', null, { id: 'dlg-org', 'aria-label': 'Organization' });
  const projSel = el('select', '', null, { id: 'dlg-project', 'aria-label': 'Project' });
  const fillProjects = (orgSlug, keep) => {
    projSel.textContent = '';
    if (ALL) projSel.append(Object.assign(el('option', '', 'Choose a project'), { value: '' }));
    PROJECTS.filter((p) => orgOf(p) === orgSlug).forEach((p) => projSel.append(Object.assign(el('option', '', p.name), { value: p.slug })));
    if (keep && [...projSel.options].some((o) => o.value === keep)) projSel.value = keep;
  };
  ORGS.forEach((o) => orgSel.append(Object.assign(el('option', '', o.name), { value: o.slug })));
  orgSel.value = here ? orgOf(here) : (ORGS[0] ? ORGS[0].slug : '');
  fillProjects(orgSel.value, slug);
  orgSel.addEventListener('change', () => fillProjects(orgSel.value));
  const dest = el('div', 'dlg-dest');
  const orgField = el('label', 'dlg-dest-field', null, { for: 'dlg-org' });
  orgField.append(el('span', 'eyebrow', 'Organization'));
  const projField = el('label', 'dlg-dest-field', null, { for: 'dlg-project' });
  projField.append(el('span', 'eyebrow', 'Add to project'));
  const wrapSel = (sel) => { const w = el('div', 'select'); w.append(sel); const c = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); c.setAttribute('class', 'chev'); c.setAttribute('viewBox', '0 0 24 24'); c.setAttribute('aria-hidden', 'true'); c.innerHTML = '<use href="#i-chevron"/>'; w.append(c); return w; };
  orgField.append(wrapSel(orgSel));
  projField.append(wrapSel(projSel));
  dest.append(orgField, projField);
  const area = el('textarea', 'dlg-area', null, { rows: '8', spellcheck: 'false', autocapitalize: 'none', 'aria-label': 'Targets',
    placeholder: 'example.com\n203.0.113.10\n10.0.0.0/28\n-not-ours.example.com   (exclude and remove)\n\nor, for several projects:\n##Acme\n#Web\nexample.com\n#Network\n10.0.0.0/28' });
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
  form.append(title, dest, lead, area, tools, el('div', 'field', null, { style: 'margin-top:12px' }), authWrap, msg, out, actions);
  form.children[4].append(mode);
  d.append(form);
  document.body.append(d);

  area.addEventListener('input', () => { count.textContent = countLabel(area.value); });
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
    if (!countEntries(area.value) && !countExclusions(area.value)) { msg.className = 'msg err'; msg.textContent = 'Paste at least one target.'; msg.style.display = 'block'; return; }
    if (!projSel.value && !isOrgFormat(area.value)) { msg.className = 'msg err'; msg.textContent = 'Choose a project to add them to, or put #Project above each list.'; msg.style.display = 'block'; return; }
    if (countEntries(area.value) && mode.value !== 'none' && !auth.checked) { msg.className = 'msg err'; msg.textContent = 'Please confirm you are authorized to test these targets.'; msg.style.display = 'block'; return; }
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
      const res = await fetch(orgMode ? '/api/v1/targets/bulk-org' : `/api/v1/projects/${encodeURIComponent(projSel.value)}/targets/bulk`, {
        method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf() },
        body: JSON.stringify({ text: area.value, discover: mode.value !== 'none', mode: mode.value === 'none' ? undefined : mode.value, current_project: orgMode && projSel.value ? projSel.value : undefined }),
      });
      const data = await res.json();
      clearInterval(ticker);
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
      const existed = orgMode ? data.projects.reduce((n, p) => n + p.already_exists.length, 0) : data.already_exists.length;
      const bad = orgMode ? data.invalid.concat(...data.projects.map((p) => p.invalid)) : data.invalid;
      const destName = (PROJECTS.find((p) => p.slug === projSel.value) || {}).name;
      const excluded = orgMode ? [].concat(...data.projects.map((p) => p.excluded || [])) : (data.excluded || []);
      const parts = [];
      if (data.created || !excluded.length) parts.push(`${data.created} added${!orgMode && destName ? ` to ${destName}` : ''}`);
      excluded.forEach((e) => parts.push(`${e.pattern} excluded (${e.hosts_removed} host${e.hosts_removed === 1 ? '' : 's'} and ${e.targets_removed} target${e.targets_removed === 1 ? '' : 's'} removed)`));
      if (orgMode && data.projects_created) parts.push(`${data.projects_created} project${data.projects_created === 1 ? '' : 's'} created`);
      if (existed) parts.push(`${existed} already existed`);
      if (bad.length) parts.push(`${bad.length} not applied`);
      if (data.discovery_started) parts.push(`${data.discovery_started} queued for discovery, in order`);
      if (data.mode_note) parts.push(data.mode_note);
      const failed = orgMode ? data.projects.filter((p) => p.error) : [];
      if (orgMode && data.organization_note) parts.push(data.organization_note);
      msg.className = `msg ${(data.created || excluded.length) && !failed.length ? 'ok' : 'err'}`;
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
        out.append(el('p', 'note', 'Not applied:'), list);
      }
      if ((data.scan_ids || []).length) {
        const watch = el('a', 'btn sm', 'Watch it live', { href: `/cve/?follow=${data.scan_ids[0]}`, style: 'display:inline-flex;align-items:center;text-decoration:none;margin-top:10px' });
        out.append(watch);
      }
      if (data.created || excluded.length) { area.value = ''; area.dispatchEvent(new Event('input')); document.dispatchEvent(new CustomEvent('cve:targets-added', { detail: data })); }
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
