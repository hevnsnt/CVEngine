// Small shared helpers for the account and administration pages (DOM built with textContent only).
export const el = (tag, cls, text, attrs = {}) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v));
  return n;
};

export function csrfToken() {
  const input = document.querySelector('[name=csrfmiddlewaretoken]');
  if (input) return input.value;
  const m = document.cookie.match(/csrftoken=([^;]+)/);
  return m ? m[1] : '';
}

export async function api(method, url, body) {
  const res = await fetch(url, {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export function toast(message, isError = false) {
  const t = el('div', `toast${isError ? ' err' : ''}`, message, { role: 'status' });
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 4000);
}

let uid = 0;
export function field(label, input, help) {
  const id = `u${uid += 1}`;
  input.id = id;
  const wrap = el('div', 'field');
  wrap.append(el('label', '', label, { for: id }), input);
  if (help) wrap.append(el('p', 'note', help, { style: 'margin:6px 0 0' }));
  return wrap;
}
export const text = (value = '', attrs = {}) => Object.assign(el('input', '', null, attrs), { value });
export function selectOf(options, value) {
  const s = el('select');
  options.forEach(([v, t]) => s.append(Object.assign(el('option', '', t), { value: v })));
  if (value != null) s.value = value;
  return s;
}
export function button(label, onClick, cls = 'btn') {
  const b = el('button', cls, label, { type: 'button' });
  b.onclick = async () => {
    b.disabled = true;
    try { await onClick(); } catch (err) { toast(err.message, true); }
    b.disabled = false;
  };
  return b;
}
export const badge = (t, cls = '') => el('span', `badge ${cls}`.trim(), t);
export const shortDate = (iso) => (iso ? iso.slice(0, 16).replace('T', ' ') : 'never');

export function dialog(title, build) {
  const d = el('dialog', 'dlg', null, { 'aria-label': title });
  const body = el('div', 'dlg-body');
  body.append(el('h2', '', title));
  d.append(body);
  document.body.append(d);
  d.addEventListener('close', () => d.remove());
  d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
  build(body, () => d.close());
  d.showModal();
  return d;
}

export function table(columns, rows) {
  const t = el('table', 'table');
  const head = el('tr');
  columns.forEach((c) => head.append(el('th', '', c.label)));
  const thead = el('thead'); thead.append(head);
  const tbody = el('tbody');
  rows.forEach((r) => {
    const tr = el('tr');
    columns.forEach((c) => {
      const td = el('td', c.cls || '', null, { 'data-label': c.label });
      const out = c.render(r);
      if (out instanceof Node) td.append(out); else td.textContent = out == null ? '' : out;
      tr.append(td);
    });
    tbody.append(tr);
  });
  t.append(thead, tbody);
  const wrap = el('div', 'table-wrap');
  wrap.append(t);
  return wrap;
}

export function tabs(root, defs, initial) {
  const bar = el('div', 'tools', null, { role: 'tablist' });
  const panel = el('div');
  root.append(bar, panel);
  async function open(name) {
    bar.querySelectorAll('button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    panel.textContent = '';
    history.replaceState(null, '', `#${name}`);
    try { await defs[name].open(panel); } catch (err) { panel.append(el('p', 'msg err', err.message)); }
  }
  Object.entries(defs).forEach(([name, d]) => {
    const b = el('button', 'btn ghost sm', d.label, { role: 'tab', 'data-tab': name, 'aria-selected': 'false' });
    b.type = 'button';
    b.onclick = () => open(name);
    bar.append(b);
  });
  open(defs[location.hash.slice(1)] ? location.hash.slice(1) : initial);
  return { open };
}

// An in-page confirmation (the browser's confirm() looks foreign and is blocked in some embeds). Resolves true or false.
export function ask(message, { title = 'Are you sure?', ok = 'Confirm', danger = true } = {}) {
  return new Promise((resolve) => {
    let answer = false;
    const d = dialog(title, (body, close) => {
      body.append(el('p', 'note', message, { style: 'font-size:14px' }));
      const actions = el('div', 'actions');
      const no = el('button', 'btn ghost', 'Cancel', { type: 'button' });
      no.onclick = close;
      const yes = el('button', `btn${danger ? ' danger' : ''}`, ok, { type: 'button' });
      yes.onclick = () => { answer = true; close(); };
      actions.append(no, yes);
      body.append(actions);
      setTimeout(() => no.focus(), 0);
    });
    d.addEventListener('close', () => resolve(answer));
  });
}
