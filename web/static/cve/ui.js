import { fmtDateTime } from '/staticfiles/cve/prefs.js';
import { fetchWithin } from '/staticfiles/cve/poll.js';

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
  // A read has a time limit (poll.js REQUEST_MS), so a request that never answers ends as an error the page can show. A write has none: it may
  // have been done by the time the limit passed, and "could not be saved" over a saved change would be wrong.
  const init = {
    method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken() },
    body: body ? JSON.stringify(body) : undefined,
  };
  const res = method === 'GET' ? await fetchWithin(url, init) : await fetch(url, init);
  let data = {};
  try { data = await res.json(); } catch (_) { /* empty */ }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// A message that says something went well goes by itself. An error stays until the person dismisses it (it is often the only explanation the
// server gave) and is announced as an alert. The stack has a ceiling: at most MAX_ERRORS cards are drawn, the same words shown again are one card
// with a count ("3 times"), and the rest are one line ("2 more errors. Dismiss to see them.") with its own Dismiss, so a failing page cannot
// bury the screen in cards.
export const MAX_ERRORS = 3;
let errorStack = null;
const errors = []; // [{message, count}], oldest first
function drawErrors() {
  if (!errorStack || !errorStack.isConnected) {
    errorStack = el('div', 'toast-stack');
    document.body.appendChild(errorStack);
  }
  const cards = errors.slice(0, MAX_ERRORS).map((entry) => {
    const t = el('div', 'toast err stays', null, { role: 'alert' });
    const close = el('button', 'toast-close', 'Dismiss', { type: 'button', 'aria-label': 'Dismiss this message' });
    close.addEventListener('click', () => { errors.splice(errors.indexOf(entry), 1); drawErrors(); });
    t.append(el('span', '', entry.count > 1 ? `${entry.message} (${entry.count} times)` : entry.message), close);
    return t;
  });
  const hidden = errors.slice(MAX_ERRORS);
  if (hidden.length) {
    const extra = hidden.reduce((n, e) => n + e.count, 0);
    const t = el('div', 'toast err stays', null, { role: 'alert' });
    const close = el('button', 'toast-close', 'Dismiss', { type: 'button', 'aria-label': 'Dismiss the other messages' });
    close.addEventListener('click', () => { errors.length = Math.min(errors.length, MAX_ERRORS); drawErrors(); });
    t.append(el('span', '', `${extra} more ${extra === 1 ? 'error' : 'errors'}. Dismiss to see them.`), close);
    cards.push(t);
  }
  while (errorStack.firstChild) errorStack.removeChild(errorStack.firstChild);
  errorStack.append(...cards);
  if (!cards.length) { errorStack.remove(); errorStack = null; }
}
export function toast(message, isError = false) {
  if (!isError) {
    const t = el('div', 'toast', message, { role: 'status' });
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 4000);
    return;
  }
  const same = errors.find((e) => e.message === message);
  if (same) same.count += 1;
  else errors.push({ message, count: 1 });
  drawErrors();
}

// The technical detail behind a plain sentence (a variable name, a file, a command): closed by default, one word to open. For the few people who
// need it; everyone else reads the sentence above it. The body is text, never HTML.
export function details(...lines) {
  const box = el('details', 'tech');
  box.append(el('summary', '', 'Details'));
  lines.filter(Boolean).forEach((line) => box.append(el('p', 'note', line)));
  return box;
}

// What a part of a page shows while its answer is on the way: a shimmering placeholder (still, when the person asked for less motion) and one
// plain line saying what is being checked. After SLOW_MS the line says it is taking longer than usual and that the page fills in by itself,
// so a wait never reads as a stuck page. role=status and aria-live make a screen reader say the line. Replace the node when the answer arrives.
export const SLOW_MS = 4000;
// live: false when the placeholder sits inside a region that is already live (one live region per container, or a reader says the line twice).
export function waiting(what, { slowMs = SLOW_MS, bars = 2, slow = false, live = true } = {}) {
  const box = el('div', 'wait', null, live ? { role: 'status', 'aria-live': 'polite' } : {});
  const line = el('p', 'note wait-line', `${what}...`);
  box.append(line);
  const longer = () => {
    line.textContent = `${what} is taking longer than usual. This page fills in by itself when it answers.`;
    box.classList.add('slow');
  };
  if (slow) longer(); // a page that redraws on its own passes what it knows, so a redraw does not restart the count
  for (let i = 0; i < bars; i += 1) box.append(el('span', 'sk-bar wait-bar', null, { 'aria-hidden': 'true' }));
  if (!slow) {
    const timer = setTimeout(longer, slowMs);
    if (timer && timer.unref) timer.unref();
    box.stop = () => clearTimeout(timer);
  }
  return box;
}

// A part of a page that could not be read says so, in plain words, and offers the same request again.
export function couldNotRead(what, retry, detail) {
  const box = el('div', 'load-error', null, { role: 'alert' });
  box.append(el('b', '', `${what} could not be read`));
  if (detail) box.append(el('span', 'note', detail));
  const again = el('button', 'btn ghost sm', 'Retry', { type: 'button' });
  again.addEventListener('click', retry);
  box.append(again);
  return box;
}

// An empty list that says what it means and what to do next: an icon from the page's sprite, a short title, one line of why, and up
// to two actions ({label, href} or {label, run}; the first is the primary button). tone "calm" is the good kind of empty, nothing to fix.
export function emptyState({ icon, title, body, actions = [], tone = '' }) {
  const box = el('div', `empty-state${tone ? ` ${tone}` : ''}`);
  if (icon) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('class', 'empty-icon');
    svg.setAttribute('width', '40');
    svg.setAttribute('height', '40');
    const use = document.createElementNS(ns, 'use');
    use.setAttribute('href', `#i-${icon}`);
    svg.append(use);
    box.append(svg);
  }
  box.append(el('p', 'empty-title', title));
  if (body) box.append(el('p', 'empty-body', body));
  if (actions.length) {
    const row = el('div', 'empty-actions');
    actions.forEach((a, i) => {
      const cls = `btn sm${i ? ' ghost' : ''}`;
      const b = a.href ? el('a', cls, a.label, { href: a.href }) : el('button', cls, a.label, { type: 'button' });
      if (a.run) b.addEventListener('click', a.run);
      row.append(b);
    });
    box.append(row);
  }
  return box;
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
export function selectOf(options, value, label) {
  const s = el('select');
  if (label) s.setAttribute('aria-label', label);  // a select with no <label> needs a name of its own
  options.forEach(([v, t]) => s.append(Object.assign(el('option', '', t), { value: v })));
  if (value != null) s.value = value;
  return s;
}
export function button(label, onClick, cls = 'btn') {
  const b = el('button', cls, label, { type: 'button' });
  b.onclick = async () => {
    const idle = b.textContent;
    b.disabled = true;
    b.textContent = 'Working…';
    try { await onClick(); } catch (err) { toast(err.message, true); }
    b.textContent = idle;
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

// A one-line button that opens its body OVER the page instead of pushing the rows down: the intro of a list page ("What is this"), a chart,
// a settings card. Escape and a press outside close it. Built with the list head (app.js listHead) on the table lists.
export function disclosure(label, ...body) {
  const d = el('details', 'what-is');
  const panel = el('div', 'what-body');
  panel.append(...body);
  d.append(el('summary', '', label), panel);
  document.addEventListener('pointerdown', (e) => { if (d.isConnected && d.open && !d.contains(e.target)) d.open = false; }, true);
  d.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape' || !d.open) return;
    e.stopPropagation();
    d.open = false;
    d.querySelector('summary').focus();
  });
  return d;
}
// A table wider than the box around it scrolls sideways (.scrolls on its .table-wrap); one that fits keeps overflow visible, which is what lets
// its header stay in view while the page scrolls. Watches every table in root, now and when its rows are redrawn.
export function watchWide(root) {
  let queued = false;
  const check = () => {
    queued = false;
    root.querySelectorAll('.table-wrap').forEach((wrap) => {
      const t = wrap.querySelector('.table');
      wrap.classList.toggle('scrolls', Boolean(t) && wrap.scrollWidth > wrap.clientWidth + 1 && t.offsetWidth > wrap.clientWidth + 1);
    });
  };
  const later = () => { if (!queued) { queued = true; requestAnimationFrame(check); } };
  if (window.ResizeObserver) new ResizeObserver(later).observe(root);
  new MutationObserver(later).observe(root, { childList: true, subtree: true });
  window.addEventListener('resize', later);
  later();
}
export const whatIs = (words) => disclosure('What is this', el('p', 'note', words));

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
      if (/\bclip\b/.test(c.cls || '')) td.title = td.textContent; // a cell kept to one line says all of itself on hover
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
    svg.setAttribute('width', '15');
    svg.setAttribute('height', '15');
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
