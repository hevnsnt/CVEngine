import { fmtDateTime } from '/staticfiles/cve/prefs.js';

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
export const shortDate = (iso) => (iso ? fmtDateTime(iso) || iso.slice(0, 16).replace('T', ' ') : 'never');

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

// Copy to the clipboard (text, or a function returning it when the value is only known at click time). Falls back to a
// hidden textarea where the Clipboard API is unavailable (plain http). Says so with the toast, which is also announced.
export async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  const area = el('textarea', '', null, { 'aria-hidden': 'true', tabindex: '-1' });
  area.style.cssText = 'position:fixed;top:-1000px;opacity:0';
  area.value = text;
  document.body.append(area);
  area.select();
  const ok = document.execCommand('copy');
  area.remove();
  if (!ok) throw new Error('copy blocked');
  return undefined;
}

export function copyButton(text, label = 'value', glyph = 'clip') {
  const NS = 'http://www.w3.org/2000/svg';
  const icon = (d) => {
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    d.forEach((part) => {
      const n = document.createElementNS(NS, part.tag);
      Object.entries(part.attrs).forEach(([k, v]) => n.setAttribute(k, v));
      svg.append(n);
    });
    return svg;
  };
  const b = el('button', 'copy-btn', null, { type: 'button', title: `Copy ${label}`, 'aria-label': `Copy ${label}` });
  const clip = glyph === 'link'
    ? icon([{ tag: 'path', attrs: { d: 'M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1' } }, { tag: 'path', attrs: { d: 'M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1' } }])
    : icon([{ tag: 'rect', attrs: { x: 9, y: 9, width: 11, height: 11, rx: 2 } }, { tag: 'path', attrs: { d: 'M5 15V6a2 2 0 0 1 2-2h9' } }]);
  clip.setAttribute('class', 'i-clip');
  const tick = icon([{ tag: 'path', attrs: { d: 'M5 12.5l4.5 4.5L19 7' } }]);
  tick.setAttribute('class', 'i-tick');
  b.append(clip, tick);
  b.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    const value = typeof text === 'function' ? text() : text;
    try {
      await copyText(value);
    } catch (_) {
      toast(`Could not copy the ${label}`, true);
      return;
    }
    b.classList.add('done');
    toast(`Copied ${label}`);
    setTimeout(() => b.classList.remove('done'), 1400);
  });
  return b;
}
